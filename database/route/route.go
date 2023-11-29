// Package route handles the logic of a route.
package route

import (
	"context"
	"database/sql"
	"errors"
	"math/rand"

	"github.com/deepsquare-io/proxy/database"
)

const subdomainLength = 8

func generateSubdomain() string {
	// Define the character set for the subdomain
	charSet := "abcdefghijklmnopqrstuvwxyz0123456789"

	// Generate a random subdomain of the specified length
	subdomain := make([]byte, subdomainLength)
	for i := range subdomain {
		subdomain[i] = charSet[rand.Intn(len(charSet))]
	}

	return string(subdomain)
}

const minPort = 30001
const maxPort = 65535

func generateRandomPort() int64 {
	return rand.Int63n(maxPort-minPort+1) + minPort
}

// Repository defines the route methods.
type Repository interface {
	GenerateRoute(ctx context.Context, userAddress string) (route string, port int64, err error)
	Get(ctx context.Context, userAddress string) (route string, port int64, err error)
	Count(ctx context.Context) (int64, error)
}

// NewRepository wraps around a SQL database to execute the route methods.
func NewRepository(db *sql.DB) Repository {
	return &repository{
		Queries: database.New(db),
	}
}

type repository struct {
	*database.Queries
}

func (r *repository) findUnusedPort(ctx context.Context) (int64, error) {
	var port int64

	for {
		port = generateRandomPort()

		used, err := r.Queries.IsPortUsed(ctx, port)
		if err != nil {
			return 0, err
		}

		if used == 0 {
			break
		}
	}

	return port, nil
}

func (r *repository) GenerateRoute(
	ctx context.Context,
	userAddress string,
) (route string, port int64, err error) {
	subdomain := generateSubdomain()
	port, err = r.findUnusedPort(ctx)
	if err != nil {
		return "", 0, err
	}
	if err := r.set(ctx, userAddress, subdomain, port); err != nil {
		return "", 0, err
	}
	return subdomain, port, nil
}

func (r *repository) set(
	ctx context.Context,
	userAddress string,
	route string,
	port int64,
) (err error) {
	_, err = r.Queries.SetRoute(ctx, database.SetRouteParams{
		UserAddress: userAddress,
		Route:       route,
		Port:        port,
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return r.Queries.CreateRoute(ctx, database.CreateRouteParams{
			UserAddress: userAddress,
			Route:       route,
			Port:        port,
		})
	}
	return err
}

// Get the value of the route of a user from the database.
func (r *repository) Get(
	ctx context.Context,
	userAddress string,
) (route string, port int64, err error) {
	resp, err := r.Queries.GetRoute(ctx, userAddress)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, nil
		}
		return "", 0, err
	}
	return resp.Route, resp.Port, nil
}
func (r *repository) Count(
	ctx context.Context,
) (int64, error) {
	return r.Queries.CountRoute(ctx)
}
