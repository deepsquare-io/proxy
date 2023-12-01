// Package route handles the logic of a route.
package route

import (
	"context"
	"database/sql"
	"errors"

	"github.com/deepsquare-io/proxy/database"
	"github.com/deepsquare-io/proxy/utils"
)

// Repository defines the route methods.
type Repository interface {
	GenerateRoute(ctx context.Context, userAddress string) (route string, port int64, err error)
	GetByUserAddress(ctx context.Context, userAddress string) (database.Route, error)
	Get(ctx context.Context, route string) (database.Route, error)
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
		port = utils.GenerateRandomPort()

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
	subdomain := utils.GenerateSubdomain()
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

// GetByUserAddress the value of the route of a user from the database.
func (r *repository) GetByUserAddress(
	ctx context.Context,
	userAddress string,
) (database.Route, error) {
	resp, err := r.Queries.GetRouteByUserAddress(ctx, userAddress)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return database.Route{}, nil
		}
		return database.Route{}, err
	}
	return resp, nil
}

// Get the value of the route of a user from the database.
func (r *repository) Get(
	ctx context.Context,
	route string,
) (database.Route, error) {
	resp, err := r.Queries.GetRoute(ctx, route)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return database.Route{}, nil
		}
		return database.Route{}, err
	}
	return resp, nil
}

func (r *repository) Count(
	ctx context.Context,
) (int64, error) {
	return r.Queries.CountRoute(ctx)
}
