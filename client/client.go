package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/deepsquare-io/proxy/api"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

// BoreClient defines bore client.
type BoreClient struct {
	sshConfig *ssh.ClientConfig
	sshClient *ssh.Client
	dialer    *net.Dialer

	remoteAddress string // Remote SSH server
	localAddress  string // Local SSH server
	secret        string
	keepAlive     bool
}

// NewBoreClient returns new instance of BoreClient.
func NewBoreClient(
	localAddress string,
	remoteAddress string,
	secret string,
	keepAlive bool,
) BoreClient {
	return BoreClient{
		sshConfig:     &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()},
		dialer:        &net.Dialer{},
		remoteAddress: remoteAddress,
		localAddress:  localAddress,
		secret:        secret,
		keepAlive:     keepAlive,
	}
}

// Run starts the client.
func (c *BoreClient) Run(ctx context.Context) error {
	// Healthcheck
	local, err := c.dialer.DialContext(ctx, "tcp", c.localAddress)
	if err != nil {
		return err
	}
	_ = local.Close()

	// SSH Client
	// Contact server
	remote, err := c.dialer.DialContext(ctx, "tcp", c.remoteAddress)
	if err != nil {
		return err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(remote, c.remoteAddress, c.sshConfig)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = sshConn.Close()
	}()
	c.sshClient = ssh.NewClient(sshConn, chans, reqs)

	// Send secret
	if c.secret != "" {
		// Send identity for port opening
		if _, _, err = c.sshClient.SendRequest(
			"set-id",
			true,
			ssh.Marshal(&api.IDRequest{
				ID: c.secret,
			}),
		); err != nil {
			return err
		}
	}

	// Handle multi call
	g, gctx := errgroup.WithContext(ctx)

	if c.keepAlive {
		g.Go(func() error {
			return keepAliveTicker(gctx, c.sshClient)
		})
	}

	// Pipe server stdout to os.Stdout
	session, err := c.sshClient.NewSession()
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = session.Close()
	}()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	g.Go(func() error {
		defer session.Close()
		_, err = io.Copy(os.Stdout, stdout)
		return err
	})

	// Listen on any IP from the server (which contains forwarded IP!)
	listener, err := c.sshClient.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	g.Go(func() error {
		defer listener.Close()
		for {
			local, err := c.dialer.DialContext(ctx, "tcp", c.localAddress)
			if err != nil {
				return err
			}

			client, err := listener.Accept()
			if err != nil {
				return err
			}

			go func() {
				if err := handleClient(ctx, local, client); err != nil {
					if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
						log.Err(err).Msg("connection ended with error")
					}
				}
			}()
		}
	})

	// Wait for graceful closure
	return g.Wait()
}

func handleClient(ctx context.Context, local net.Conn, remote net.Conn) error {
	defer local.Close()
	defer remote.Close()

	g, ctx := errgroup.WithContext(ctx)

	// Pipe local stdout to remote stdin
	g.Go(func() error {
		_, _ = io.Copy(local, remote)
		return io.EOF
	})

	// Pipe local stdout to remote stdin
	g.Go(func() error {
		_, _ = io.Copy(remote, local)
		return io.EOF
	})

	<-ctx.Done()
	return ctx.Err()
}

func keepAliveTicker(ctx context.Context, client *ssh.Client) error {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if _, _, err := client.SendRequest("keepalive", true, nil); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
