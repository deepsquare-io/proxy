package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	_ "embed"

	"github.com/deepsquare-io/proxy/auth"
	"github.com/deepsquare-io/proxy/database/route"
	"github.com/deepsquare-io/proxy/jwt"
	"github.com/rs/zerolog/log"
)

//go:embed response.html
var responseFormat string

// ethResponse is the expected response from the authenticator.
type ethResponse struct {
	Address string `json:"address"`
	Data    []byte `json:"data"`
	Sig     []byte `json:"sig"`
}

func formatResponse(
	publicDomain string,
	route string,
	port int64,
	token string,
	expiresAt time.Time,
) string {
	return fmt.Sprintf(responseFormat,
		route, publicDomain,
		route, publicDomain,
		publicDomain, port,
		token,
		expiresAt,
	)
}

// GenerateRoute validate the message and send back a token.
func GenerateRoute(
	publicDomain string,
	routes route.Repository,
	auth *auth.Auth,
	jwtSecret jwt.Secret,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refresh := false
		args := r.URL.Query()
		if args.Get("retrieve") == "true" {
			refresh = true
		}

		var rep ethResponse
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Err(err).Msg("failed to read body")
			http.Error(
				w,
				fmt.Sprintf("failed to read body: %s", err),
				http.StatusInternalServerError,
			)
			return
		}
		if err := json.Unmarshal(body, &rep); err != nil {
			log.Err(err).Str("body", string(body)).Msg("invalid body")
			http.Error(
				w,
				fmt.Sprintf("%s: %s", err, string(body)),
				http.StatusInternalServerError,
			)
			return
		}

		// Verify challenge
		address := strings.ToLower(rep.Address)
		if err := auth.Verify(r.Context(), address, rep.Data, rep.Sig); err != nil {
			log.Err(err).Msg("authentication failure")
			http.Error(
				w,
				fmt.Sprintf("authentication failure: %s", err),
				http.StatusInternalServerError,
			)
			return
		}

		// Create a session key
		claims, token, err := jwtSecret.GenerateToken(address, address)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var route string
		var port int64
		if refresh {
			r, err := routes.GetByUserAddress(r.Context(), rep.Address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			route = r.Route
			port = r.Port
		}
		if route == "" {
			route, port, err = routes.GenerateRoute(r.Context(), rep.Address)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		fmt.Fprint(w, formatResponse(publicDomain, route, port, token, claims.ExpiresAt.Time))
	}
}

// RetrieveRoute fetch the route based on the token.
func RetrieveRoute(
	publicDomain string,
	routes route.Repository,
	jwtSecret jwt.Secret,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		args := r.URL.Query()

		token := args.Get("token")

		// Verify token
		claims, err := jwtSecret.VerifyToken(token)
		if err != nil {
			http.Error(
				w,
				fmt.Sprintf("token verification failed: %s", err),
				http.StatusBadRequest,
			)
			return
		}

		rr, err := routes.GetByUserAddress(r.Context(), claims.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, formatResponse(publicDomain, rr.Route, rr.Port, token, claims.ExpiresAt.Time))
	}
}
