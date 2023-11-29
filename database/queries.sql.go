// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.23.0
// source: queries.sql

package database

import (
	"context"
	"time"
)

const createNonce = `-- name: CreateNonce :exec
INSERT INTO nonces (nonce, expiration) VALUES (?, ?)
`

type CreateNonceParams struct {
	Nonce      string
	Expiration time.Time
}

func (q *Queries) CreateNonce(ctx context.Context, arg CreateNonceParams) error {
	_, err := q.db.ExecContext(ctx, createNonce, arg.Nonce, arg.Expiration)
	return err
}

const createRoute = `-- name: CreateRoute :exec
INSERT INTO routes (user_address, route, port) VALUES (?, ?, ?)
`

type CreateRouteParams struct {
	UserAddress string
	Route       string
	Port        int64
}

func (q *Queries) CreateRoute(ctx context.Context, arg CreateRouteParams) error {
	_, err := q.db.ExecContext(ctx, createRoute, arg.UserAddress, arg.Route, arg.Port)
	return err
}

const getNonce = `-- name: GetNonce :one
SELECT nonce, expiration FROM nonces WHERE nonce = ? AND expiration > ? LIMIT 1
`

type GetNonceParams struct {
	Nonce      string
	Expiration time.Time
}

func (q *Queries) GetNonce(ctx context.Context, arg GetNonceParams) (Nonce, error) {
	row := q.db.QueryRowContext(ctx, getNonce, arg.Nonce, arg.Expiration)
	var i Nonce
	err := row.Scan(&i.Nonce, &i.Expiration)
	return i, err
}

const getRoute = `-- name: GetRoute :one

SELECT user_address, route, port FROM routes WHERE user_address = ? LIMIT 1
`

// -
func (q *Queries) GetRoute(ctx context.Context, userAddress string) (Route, error) {
	row := q.db.QueryRowContext(ctx, getRoute, userAddress)
	var i Route
	err := row.Scan(&i.UserAddress, &i.Route, &i.Port)
	return i, err
}

const isPortUsed = `-- name: IsPortUsed :one
SELECT COUNT(*) FROM routes WHERE port = ?
`

func (q *Queries) IsPortUsed(ctx context.Context, port int64) (int64, error) {
	row := q.db.QueryRowContext(ctx, isPortUsed, port)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const setRoute = `-- name: SetRoute :one
UPDATE routes SET route = ?, port = ? WHERE user_address = ? RETURNING route
`

type SetRouteParams struct {
	Route       string
	Port        int64
	UserAddress string
}

func (q *Queries) SetRoute(ctx context.Context, arg SetRouteParams) (string, error) {
	row := q.db.QueryRowContext(ctx, setRoute, arg.Route, arg.Port, arg.UserAddress)
	var route string
	err := row.Scan(&route)
	return route, err
}

const updateNonce = `-- name: UpdateNonce :one
UPDATE nonces SET expiration = ? WHERE nonce = ? RETURNING nonce
`

type UpdateNonceParams struct {
	Expiration time.Time
	Nonce      string
}

func (q *Queries) UpdateNonce(ctx context.Context, arg UpdateNonceParams) (string, error) {
	row := q.db.QueryRowContext(ctx, updateNonce, arg.Expiration, arg.Nonce)
	var nonce string
	err := row.Scan(&nonce)
	return nonce, err
}
