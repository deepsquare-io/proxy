// Package nonce handles the logic of a nonce.
package nonce

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/deepsquare-io/proxy/database"
)

const expirationDuration = 10 * time.Minute

const nonceLength = 16 // You can adjust the length as needed

func generateNonce() (string, error) {
	// Create a byte slice to store the random nonce
	nonce := make([]byte, nonceLength)

	// Use the crypto/rand package to generate random bytes
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}

	nonceString := base64.StdEncoding.EncodeToString(nonce)

	return nonceString, nil
}

// Repository defines the nonce methods.
type Repository interface {
	Generate(ctx context.Context) (string, error)
	IsValid(ctx context.Context, nonce string) (bool, error)
}

// NewRepository wraps around a SQL database to execute the nonce methods.
func NewRepository(db *sql.DB) Repository {
	return &repository{
		Queries: database.New(db),
	}
}

type repository struct {
	*database.Queries
}

func (r *repository) Generate(ctx context.Context) (string, error) {
	nonce, err := generateNonce()
	if err != nil {
		panic(err)
	}
	if err := r.set(ctx, nonce, time.Now().Add(expirationDuration)); err != nil {
		return "", err
	}
	return nonce, nil
}

func (r *repository) set(ctx context.Context, value string, expiration time.Time) (err error) {
	_, err = r.Queries.UpdateNonce(ctx, database.UpdateNonceParams{
		Nonce:      value,
		Expiration: expiration,
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return r.Queries.CreateNonce(ctx, database.CreateNonceParams{
			Nonce:      value,
			Expiration: expiration,
		})
	}
	return err
}

func (r *repository) IsValid(ctx context.Context, existing string) (bool, error) {
	_, err := r.Queries.GetNonce(ctx, database.GetNonceParams{
		Nonce:      existing,
		Expiration: time.Now(),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
