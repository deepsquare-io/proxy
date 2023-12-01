package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/template"

	"embed"

	"github.com/deepsquare-io/proxy/auth"
	"github.com/deepsquare-io/proxy/database"
	"github.com/deepsquare-io/proxy/database/nonce"
	"github.com/deepsquare-io/proxy/database/route"
	"github.com/deepsquare-io/proxy/handler"
	"github.com/deepsquare-io/proxy/jwt"
	proxyssh "github.com/deepsquare-io/proxy/ssh"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

var (
	//go:embed pages/* components/* base.html base.htmx
	html         embed.FS
	version      = "dev"
	key          []byte
	jwtSecret    string
	publicDomain string

	sshListenAddress  string
	httpListenAddress string
	keysDir           string

	insecure  bool
	anonymous bool

	dbFile string
)

func generateKeyPair(dirPath string, keyType string) (filePath string, err error) {
	var data []byte

	filePath = filepath.Join(dirPath, "ssh_host_"+keyType+"_key")
	if _, err := os.Stat(filePath); !errors.Is(err, os.ErrNotExist) {
		log.Info().Str("path", filePath).Msg("key exist")
		return filePath, nil
	}

	privateKeyFile, err := os.Create(filePath)
	if err != nil {
		return filePath, err
	}
	defer func() {
		_ = privateKeyFile.Close()
		_ = os.Chmod(filePath, 0600)
	}()

	switch keyType {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return filePath, err
		}
		data = x509.MarshalPKCS1PrivateKey(privateKey)
		if err = pem.Encode(privateKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: data}); err != nil {
			return filePath, err
		}
	case "ecdsa":
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return filePath, err
		}
		data, err = x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return filePath, err
		}
		if err = pem.Encode(privateKeyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: data}); err != nil {
			return filePath, err
		}
	case "ed25519":
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return filePath, err
		}
		data, err = x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return filePath, err
		}
		if err = pem.Encode(privateKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: data}); err != nil {
			return filePath, err
		}
	default:
		return filePath, fmt.Errorf("unsupported key type: %s", keyType)
	}
	return filePath, err
}

func loadKey(config *ssh.ServerConfig, filePath string) error {
	pk, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	private, err := ssh.ParsePrivateKey(pk)
	if err != nil {
		return err
	}
	config.AddHostKey(private)
	return nil
}

var app = &cli.App{
	Name:    "dpsproxy-server",
	Version: version,
	Usage:   "DeepSquare dynamic reverse proxy.",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:        "public-domain",
			Usage:       "The public domain name of this server.",
			Destination: &publicDomain,
			EnvVars:     []string{"PUBLIC_DOMAIN"},
		},
		&cli.StringFlag{
			Name:        "http.listenAddress",
			Usage:       "The HTTP server listening address.",
			Destination: &httpListenAddress,
			Value:       ":3000",
			EnvVars:     []string{"HTTP_LISTEN_ADDRESS"},
		},
		&cli.StringFlag{
			Name:        "ssh.listenAddress",
			Usage:       "The SSH server listening address.",
			Destination: &sshListenAddress,
			Value:       ":2200",
			EnvVars:     []string{"SSH_LISTEN_ADDRESS"},
		},
		&cli.StringFlag{
			Name:        "ssh.keysDir",
			Usage:       "A directory used to store host keys.",
			Destination: &keysDir,
			Value:       "./",
			EnvVars:     []string{"KEYS_DIR"},
		},
		&cli.StringFlag{
			Name:  "csrf.secret",
			Usage: "A 32 bytes hex secret",
			Action: func(ctx *cli.Context, s string) error {
				data, err := hex.DecodeString(s)
				if err != nil {
					panic(err)
				}
				key = data
				return nil
			},
			EnvVars: []string{"CSRF_SECRET"},
		},
		&cli.StringFlag{
			Name:        "jwt.secret",
			Usage:       "A unique string secret",
			Destination: &jwtSecret,
			EnvVars:     []string{"JWT_SECRET"},
		},
		&cli.StringFlag{
			Name:        "db.path",
			Value:       "./db.sqlite3",
			Destination: &dbFile,
			Usage:       "SQLite3 database file path.",
			EnvVars:     []string{"DB_PATH"},
		},
		&cli.BoolFlag{
			Name:        "insecure",
			Value:       false,
			Destination: &insecure,
			Usage:       "Allow CSRF tokens in insecure connections.",
		},
		&cli.BoolFlag{
			Name:        "anonymous",
			Value:       false,
			Destination: &anonymous,
			Usage:       "Allow anonymous login.",
		},
	},
	Suggest: true,
	Action: func(cCtx *cli.Context) error {
		ctx := cCtx.Context
		ctx, cancel := context.WithCancel(ctx)

		log.Level(zerolog.DebugLevel)

		// Handle cancellation
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-ch
			cancel()
		}()

		// SSH config
		var config ssh.ServerConfig
		_ = os.MkdirAll(keysDir, 0700)
		filePath, err := generateKeyPair(keysDir, "rsa")
		if err != nil {
			return err
		}
		if err := loadKey(&config, filePath); err != nil {
			return err
		}
		filePath, err = generateKeyPair(keysDir, "ecdsa")
		if err != nil {
			return err
		}
		if err := loadKey(&config, filePath); err != nil {
			return err
		}
		filePath, err = generateKeyPair(keysDir, "ed25519")
		if err != nil {
			return err
		}
		if err := loadKey(&config, filePath); err != nil {
			return err
		}

		// Router
		r := chi.NewRouter()
		r.Use(hlog.NewHandler(log.Logger))

		// DB
		d, err := sql.Open("sqlite", dbFile)
		if err != nil {
			log.Error().Err(err).Msg("db failed")
			return err
		}
		if err := database.InitialMigration(d); err != nil {
			log.Error().Err(err).Msg("db migration failed")
			return err
		}

		nonces := nonce.NewRepository(d)
		routes := route.NewRepository(d)

		// Auth
		authService := auth.NewAuth(nonces)

		r.Get("/challenge", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, authService.Challenge(r.Context(), "login"))
		})

		// Backend
		r.Post(
			"/routes",
			handler.GenerateRoute(publicDomain, routes, authService, jwt.Secret(jwtSecret)),
		)
		r.Get(
			"/routes",
			handler.RetrieveRoute(publicDomain, routes, jwt.Secret(jwtSecret)),
		)

		// Pages rendering
		var renderFn http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Clean(r.URL.Path)
			path = filepath.Clean(fmt.Sprintf("pages/%s/page.tmpl", path))

			// Check if SSR
			var base string
			if r.Header.Get("Hx-Request") != "true" {
				// Initial Rendering
				base = "base.html"
			} else {
				// SSR
				base = "base.htmx"
			}
			t, err := template.ParseFS(html, base, path, "components/*")
			if err != nil {
				// The page doesn't exist
				http.Error(w, "not found", http.StatusNotFound)
				return
			}

			// Special rules
			switch path {
			case "pages/page.tmpl":
				count, err := routes.Count(r.Context())
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if err := t.ExecuteTemplate(w, "base", struct {
					CSRFToken  string
					RouteCount int64
				}{
					CSRFToken:  csrf.Token(r),
					RouteCount: count,
				}); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			default:
				if err := t.ExecuteTemplate(w, "base", struct {
					CSRFToken string
				}{
					CSRFToken: csrf.Token(r),
				}); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}
		}
		r.Get("/*", renderFn)

		server := proxyssh.NewServer(
			sshListenAddress,
			&config,
			jwt.Secret(jwtSecret),
			routes,
			publicDomain,
			anonymous,
		)

		go func() {
			err := server.Serve(ctx)
			log.Fatal().Err(err).Msg("ssh crashed")
		}()

		log.Info().Msg("listening")
		return http.ListenAndServe(
			httpListenAddress,
			server.ForwardHTTP(csrf.Protect(key, csrf.Secure(!insecure))(r)),
		)
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
