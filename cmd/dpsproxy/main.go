package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deepsquare-io/proxy/client"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

var (
	version    string
	remoteAddr string
	localAddr  string
	keepAlive  bool
	secret     string
	reconnect  bool
)

var app = &cli.App{
	Name:    "dpsproxy",
	Version: version,
	Usage:   "DeepSquare Proxy",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:        "to.addr",
			Usage:       "Address of the remote bore proxy.",
			Destination: &remoteAddr,
		},
		&cli.StringFlag{
			Name:        "local.addr",
			Usage:       "Local address to be forwarded.",
			Destination: &localAddr,
		},
		&cli.BoolFlag{
			Name:        "keep-alive",
			Usage:       "Local address to be forwarded.",
			Destination: &keepAlive,
		},
		&cli.StringFlag{
			Name:        "secret",
			Usage:       "Secret used for authentication.",
			Destination: &secret,
		},
		&cli.BoolFlag{
			Name:        "reconnect",
			Usage:       "Auto reconnect.",
			Destination: &reconnect,
			Aliases:     []string{"r"},
		},
	},
	Action: func(cCtx *cli.Context) error {
		ctx := cCtx.Context
		ctx, cancel := context.WithCancel(ctx)

		// Handle cancellation
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-ch
			cancel()
		}()

		client := client.NewBoreClient(localAddr, remoteAddr, secret, keepAlive)

		for {
			if err := client.Run(ctx); err != nil {
				if reconnect {
					if errors.Is(err, io.EOF) {
						return nil
					}
					log.Err(err).Msg("client failure")
					select {
					case <-time.After(time.Second * 10):
						continue
					case <-ctx.Done():
						return err
					}
				}
				return err
			}
		}
	},
}

func main() {
	log.Logger = log.With().Caller().Logger().Output(zerolog.ConsoleWriter{Out: os.Stderr})
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("app crashed")
	}
}
