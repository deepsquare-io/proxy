// Package ssh is used to handle SSH connections and forwarding.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/deepsquare-io/proxy/api"
	"github.com/deepsquare-io/proxy/database/route"
	"github.com/deepsquare-io/proxy/jwt"
	"github.com/deepsquare-io/proxy/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yhat/wsutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

type client struct {
	claims   *jwt.Claims
	claimsMu sync.RWMutex

	channel   ssh.Channel
	channelMu sync.RWMutex

	// Dependencies
	jwt           jwt.Service
	routes        route.Repository
	domain        string
	indexedRoutes map[string]string
	anonymous     bool

	log zerolog.Logger
}

func (c *client) handleChannels(nchans <-chan ssh.NewChannel) error {
	for nch := range nchans {
		ch, _, err := nch.Accept()
		if err != nil {
			log.Err(err).Msg("couldn't accept channel")
			return err
		}
		c.channelMu.Lock()
		c.channel = ch
		c.channelMu.Unlock()
	}
	return io.EOF
}

func (c *client) write(data string) {
	c.channelMu.RLock()
	defer c.channelMu.RUnlock()
	if c.channel != nil {
		_, _ = io.WriteString(c.channel, data)
	}
}

func (c *client) setClaims(claims *jwt.Claims) {
	c.claimsMu.Lock()
	c.claims = claims
	c.claimsMu.Unlock()
}

func (c *client) getClaims() *jwt.Claims {
	c.claimsMu.RLock()
	defer c.claimsMu.RUnlock()
	return c.claims
}

// Server using SSH with tcp forwarding.
type Server struct {
	addr string
	*ssh.ServerConfig

	jwt       jwt.Service
	routes    route.Repository
	domain    string
	anonymous bool

	// map subdomain to address
	indexedRoutes map[string]string
}

// NewServer instanciates a new ssh server with tcp forwarding.
func NewServer(
	listenAddress string,
	config *ssh.ServerConfig,
	jwt jwt.Service,
	routes route.Repository,
	domain string,
	anonymous bool,
) *Server {
	config.NoClientAuth = true
	return &Server{
		addr:          listenAddress,
		ServerConfig:  config,
		jwt:           jwt,
		routes:        routes,
		domain:        domain,
		anonymous:     anonymous,
		indexedRoutes: make(map[string]string),
	}
}

// Serve executes the listening loop and logic.
func (s *Server) Serve(ctx context.Context) error {
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	defer func() {
		log.Info().Msg("listener (server) ended")
		_ = listener.Close()
	}()

	log.Info().Str("addr", s.addr).Msg("ssh server is listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			log.Err(err).Msg("failed to accept connection")
			return err
		}

		// Handle each client connection
		go func() {
			defer func() {
				log.Info().Msg("client connection ended")
				_ = conn.Close()
			}()
			log.Info().
				Str("remote", conn.RemoteAddr().String()).
				Msg("new connection")

			sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.ServerConfig)
			if err != nil {
				log.Warn().Err(err).Msg("ssh failure")
				return
			}
			defer sshConn.Close()
			client := &client{
				jwt:           s.jwt,
				routes:        s.routes,
				domain:        s.domain,
				indexedRoutes: s.indexedRoutes,
				anonymous:     s.anonymous,

				log: log.With().Str("remote", conn.RemoteAddr().String()).Logger(),
			}

			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				if err := client.handleRequests(ctx, sshConn, reqs); err != nil && err != io.EOF &&
					errors.Is(err, context.Canceled) {
					client.log.Err(err).Msg("ssh requests ended in error")
				}
				return io.EOF
			})
			g.Go(func() error {
				if err := client.handleChannels(chans); err != nil && err != io.EOF &&
					errors.Is(err, context.Canceled) {
					client.log.Err(err).Msg("ssh channels ended in error")
				}
				return io.EOF
			})
			_ = g.Wait()
		}()
	}
}

func (c *client) handleRequests(
	ctx context.Context,
	sshServerConn ssh.Conn,
	reqs <-chan *ssh.Request,
) error {
	for req := range reqs {
		switch req.Type {
		case "set-id":
			c.handleSetID(ctx, req)
			continue

		case "tcpip-forward":
			// Fire-and-forget
			go func(req *ssh.Request) {
				err := c.handleTCPIPForward(ctx, sshServerConn, req)
				c.log.Err(err).Msg("tcpip-forward ended")
			}(req)

		default:
			if req.WantReply {
				_ = req.Reply(false, []byte{})
			}
		}
	}
	return nil
}

func (c *client) handleSetID(ctx context.Context, req *ssh.Request) {
	// Reply as true to ignore use user-less instead.

	var payload api.IDRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		c.log.Err(err).Str("payload", string(req.Payload)).Msg("failed to unmarshal request")
		_ = req.Reply(false, []byte{})
		return
	}
	if payload.ID == "" {
		c.log.Warn().Str("payload", string(req.Payload)).Msg("set-id payload is empty")
		_ = req.Reply(false, []byte{})
		return
	}

	claims, err := c.jwt.VerifyToken(ctx, payload.ID)
	if err != nil {
		c.log.Err(err).Str("token", payload.ID).Msg("failed jwt verification")
		_ = req.Reply(false, []byte{})
		return
	}
	c.setClaims(claims)

	c.log = c.log.With().Str("id", claims.UserID).Logger()

	_ = req.Reply(true, []byte{})
}

func (c *client) handleTCPIPForward(
	ctx context.Context,
	sshServerConn ssh.Conn,
	req *ssh.Request,
) error {
	var lc net.ListenConfig
	var payload api.ChannelForwardRequest
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		c.log.Err(err).Str("payload", string(req.Payload)).Msg("failed to unmarshal request")
		_ = req.Reply(false, []byte{})
		return nil
	}

	claims := c.getClaims()
	var route string
	var port int64
	var err error
	if claims != nil {
		r, err := c.routes.GetByUserAddress(ctx, claims.UserID)
		if err != nil {
			c.log.Err(err).Str("address", claims.UserID).Msg("failed to fetch route")
			_ = req.Reply(false, []byte{})
			return err
		}
		route = r.Route
		port = r.Port
	} else {
		if c.anonymous {
			c.log.Warn().Msg("anonymous login")
			route = utils.GenerateSubdomain()
			port = utils.GenerateSafeRandomPort()
		} else {
			c.log.Error().Msg("anonymous login is not allowed")
			_ = req.Reply(false, []byte{})
			return err
		}
	}

	listenAddress := fmt.Sprintf("%s:%d", payload.Addr, port)

	// Indexing so it can be used with http
	c.indexedRoutes[route] = listenAddress
	log.Warn().Str("route", route).Msg("route added")
	defer func() {
		log.Warn().Str("route", route).Msg("route deleted")
		delete(c.indexedRoutes, route)
	}()

	listener, err := lc.Listen(ctx, "tcp", listenAddress)
	if err != nil {
		c.log.Err(err).Str("listenAddress", listenAddress).Msg("cannot open port for client")
		_ = req.Reply(false, []byte{})
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	defer func() {
		c.log.Info().Msg("client open port closed")
		_ = listener.Close()
	}()
	c.log.Warn().Str("listenAddress", listenAddress).Msg("port opened for client")
	_ = req.Reply(true, ssh.Marshal(&api.ChannelForwardReply{
		Port: uint32(port),
	}))
	c.write(renderOutput(route, c.domain, port))

	for {
		conn, err := listener.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				c.log.Warn().Err(err).Msg("accept failed with timeout")
				continue
			}
			c.log.Warn().Err(err).Msg("accept failed")

			return err
		}

		go func() {
			defer func() {
				c.log.Info().Msg("tcpip forwarding connection ended")
				_ = conn.Close()
			}()

			remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
			if !ok {
				panic("couldn't parse remote addr to tcp addr?!")
			}
			laddr := payload.Addr
			lport := uint32(port)
			raddr := remoteAddr.IP.String()
			rport := uint32(remoteAddr.Port)

			p := api.ForwardedTCPPayload{
				Addr:       laddr,
				Port:       lport,
				OriginAddr: raddr,
				OriginPort: rport,
			}
			ch, reqs, err := sshServerConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&p))
			if err != nil {
				c.log.Err(err).Any("payload", p).Msg("couldn't open forwarded-tcpip channel")
				return
			}
			defer ch.Close()

			c.log.Info().Any("payload", p).Msg("tcpip forwarding connection start")
			defer c.log.Info().Any("payload", p).Msg("tcpip forwarding connection closed")

			g, ctx := errgroup.WithContext(ctx)
			g.Go(func() error {
				ssh.DiscardRequests(reqs)
				return io.EOF
			})
			g.Go(func() error {
				return c.pipe(ctx, ch, conn)
			})

			// Exit on first error
			<-ctx.Done()
		}()
	}
}

func (c *client) pipe(ctx context.Context, ch ssh.Channel, conn net.Conn) error {
	g, ctx := errgroup.WithContext(ctx)

	// Pipe local stdout to remote stdin
	g.Go(func() error {
		_, _ = io.Copy(ch, conn)
		return io.EOF
	})

	// Pipe local stdout to remote stdin
	g.Go(func() error {
		_, _ = io.Copy(conn, ch)
		return io.EOF
	})

	// Exit on first error
	<-ctx.Done()
	return ctx.Err()
}

// ForwardHTTP is a middleware that forwards HTTP request based on the subdomain
// to a corresponding SSH client.
func (s *Server) ForwardHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}

		if subdomain, _, ok := strings.Cut(host, "."); host != s.domain && ok {
			if addr, ok := s.indexedRoutes[subdomain]; ok {
				w.Header().Set("X-Proxy", "bore")

				if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
					url := &url.URL{
						Scheme: "ws",
						Host:   addr,
					}
					wsutil.NewSingleHostReverseProxy(url).ServeHTTP(w, r)
					return
				}

				url := &url.URL{Scheme: "http", Host: addr}
				httputil.NewSingleHostReverseProxy(url).ServeHTTP(w, r)
				return
			}

			url := &url.URL{
				Scheme: r.URL.Scheme,
				Host:   s.domain,
			}
			http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
			return
		}

		next.ServeHTTP(w, r)
	})
}
