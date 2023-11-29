package client

import (
	"context"
	"io"
	"net"
	"os"
	"time"

	"github.com/deepsquare-io/proxy/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

// BoreClient defines bore client.
type BoreClient struct {
	sshConfig *ssh.ClientConfig
	sshClient *ssh.Client
	dialer    *net.Dialer

	remoteAddress string
	localAddress  string
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
	remote, err := c.dialer.DialContext(ctx, "tcp", c.remoteAddress)
	if err != nil {
		return err
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(remote, c.remoteAddress, c.sshConfig)
	if err != nil {
		return err
	}
	c.sshClient = ssh.NewClient(sshConn, chans, reqs)

	// Send secret
	if c.secret != "" {
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
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	g.Go(func() error {
		defer session.Close()
		_, err = io.Copy(os.Stdout, stdout)
		return err
	})

	listener, err := c.sshClient.Listen("tcp", c.remoteAddress)
	if err != nil {
		return err
	}

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

			go handleClient(ctx, local, client)
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
		_, err := io.Copy(local, remote)
		return err
	})

	// Pipe local stdout to remote stdin
	g.Go(func() error {
		_, err := io.Copy(remote, local)
		return err
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
