// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.23.0

package database

import (
	"database/sql"
	"time"
)

type Nonce struct {
	Nonce      string
	Expiration time.Time
	Ref        sql.NullString
}

type Route struct {
	UserAddress string
	Route       string
	Port        int64
}
