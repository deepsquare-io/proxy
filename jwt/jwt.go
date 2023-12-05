// Package jwt defines all the methods for JWT manipulation.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/deepsquare-io/proxy/database/nonce"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// ExpiresDuration is the duration when a user session expires.
const ExpiresDuration = 24 * time.Hour

// Claims are the fields stored in a JWT.
type Claims struct {
	jwt.RegisteredClaims
	UserID   string `json:"user_id"`
	UserName string `json:"user_name"`
	Nonce    string `json:"nonce"`
}

// Service handles common JWT manipulation.
type Service struct {
	Secret []byte
	Nonces nonce.Repository
}

// GenerateToken creates a JWT session token which stores the user identity.
//
// The returned token is signed with the JWT secret, meaning it cannot be falsified.
func (s *Service) GenerateToken(
	ctx context.Context,
	userID string,
	userName string,
	long bool,
) (claims *Claims, signed string) {
	// Create the token claims
	exp := ExpiresDuration
	if long {
		exp = ExpiresDuration + 8760*time.Hour
	}

	// Clear old
	if err := s.Nonces.ClearByRef(ctx, userID); err != nil {
		log.Warn().Err(err).Msg("failed to clear old token")
	}

	nonce, err := s.Nonces.Generate(ctx, nonce.WithExpiration(exp), nonce.WithRef(userID))
	if err != nil {
		panic(err)
	}
	claims = &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(exp)),
		},
		UserID:   userID,
		UserName: userName,
		Nonce:    nonce,
	}

	// Create the token object
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(s.Secret)
	if err != nil {
		panic(err)
	}

	return claims, tokenString
}

// VerifyToken checks if the token signature is valid compared to the JWT secret.
func (s *Service) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	// Parse the token
	var claims Claims
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			// Make sure the signing method is HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}

			// Return the secret key for validation
			return []byte(s.Secret), nil
		},
	)
	if err != nil {
		return nil, err
	}

	// Verify and return the claims
	if ok, err := s.Nonces.IsValid(ctx, claims.Nonce); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("nonce is invalid")
	}

	if token.Valid {
		return &claims, nil
	}

	return nil, errors.New("invalid token")
}
