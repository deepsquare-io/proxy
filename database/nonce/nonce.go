// Package nonce handles the logic of a nonce.
package nonce

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/deepsquare-io/proxy/database"
)

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

type GenerateOption func(*GenerateOptions)

type GenerateOptions struct {
	expiration time.Duration
	ref        string
}

func applyGenerateOptions(opts []GenerateOption) *GenerateOptions {
	o := &GenerateOptions{
		expiration: 10 * time.Minute,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func WithExpiration(expiration time.Duration) GenerateOption {
	return func(o *GenerateOptions) {
		o.expiration = expiration
	}
}

func WithRef(ref string) GenerateOption {
	return func(o *GenerateOptions) {
		o.ref = ref
	}
}

// Repository defines the nonce methods.
type Repository interface {
	Generate(ctx context.Context, opts ...GenerateOption) (string, error)
	IsValid(ctx context.Context, nonce string) (bool, error)
	ClearByRef(ctx context.Context, ref string) error
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

func (r *repository) Generate(ctx context.Context, opts ...GenerateOption) (string, error) {
	o := applyGenerateOptions(opts)
	nonce, err := generateNonce()
	if err != nil {
		panic(err)
	}
	if err := r.set(ctx, nonce, time.Now().Add(o.expiration), o.ref); err != nil {
		return "", err
	}
	return nonce, nil
}

func (r *repository) set(
	ctx context.Context,
	value string,
	expiration time.Time,
	ref string,
) (err error) {
	fmt.Printf("value=%s ref=%s\n", value, ref)
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
			Ref: sql.NullString{
				String: ref,
				Valid:  ref != "",
			},
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

func (r *repository) ClearByRef(ctx context.Context, ref string) error {
	return r.Queries.DeleteNoncesByRef(ctx, sql.NullString{
		String: ref,
		Valid:  true,
	})
}
