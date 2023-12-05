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
	jwt jwt.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		generate, remember := false, false
		args := r.URL.Query()
		if args.Get("generate") == "true" {
			generate = true
		}
		if args.Get("remember") == "true" || args.Get("remember") == "on" {
			remember = true
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
		claims, token := jwt.GenerateToken(r.Context(), address, address, remember)

		var route string
		var port int64
		if !generate {
			r, _ := routes.GetByUserAddress(r.Context(), rep.Address)
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
