/*
Auth Web3 HTMX is a simple demonstration of Web3 in combination with HTMX, written in Go.
*/package main

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"embed"

	"github.com/deepsquare-io/proxy/auth"
	"github.com/deepsquare-io/proxy/database"
	"github.com/deepsquare-io/proxy/database/nonce"
	"github.com/deepsquare-io/proxy/database/route"
	"github.com/deepsquare-io/proxy/handler"
	"github.com/deepsquare-io/proxy/jwt"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

var (
	//go:embed pages/* components/* base.html base.htmx
	html         embed.FS
	version      = "dev"
	key          []byte
	jwtSecret    string
	publicDomain string

	dbFile string
)

var app = &cli.App{
	Name:    "dpsproxy-server",
	Version: version,
	Usage:   "Demo of Auth and HTMX.",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:        "public-domain",
			Usage:       "The public domain name of this server.",
			Destination: &publicDomain,
			EnvVars:     []string{"PUBLIC_DOMAIN"},
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
	},
	Suggest: true,
	Action: func(cCtx *cli.Context) error {
		log.Level(zerolog.DebugLevel)

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
		authService := auth.NewAuth(jwt.Secret(jwtSecret), nonces)

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
			if err := t.ExecuteTemplate(w, "base", struct {
				CSRFToken string
			}{
				CSRFToken: csrf.Token(r),
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
		r.Get("/*", renderFn)

		log.Info().Msg("listening")
		return http.ListenAndServe(":3000", csrf.Protect(key)(r))
	},
}

func main() {
	log.Logger = log.With().Caller().Logger()
	_ = godotenv.Load(".env.local")
	_ = godotenv.Load(".env")
	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err).Msg("app crashed")
	}
}
