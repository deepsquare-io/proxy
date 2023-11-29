// Package auth defines the authentication layer of the application.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/deepsquare-io/proxy/database/nonce"
	"github.com/deepsquare-io/proxy/jwt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog/log"
)

// Auth is a service that provides HTTP handlers and middlewares used for authentication.
//
// It uses a time-based nonce. The nonce is encrypted with the private key.
type Auth struct {
	jwtSecret jwt.Secret
	nonces    nonce.Repository
}

// NewAuth builds the Auth struct.
func NewAuth(
	jwtSecret jwt.Secret,
	nonces nonce.Repository,
) *Auth {
	return &Auth{
		jwtSecret: jwtSecret,
		nonces:    nonces,
	}
}

type challengeMessage struct {
	Message string `json:"message"`
	Nonce   string `json:"nonce"`
}

// Challenge returns a message with a nonce.
func (a *Auth) Challenge(ctx context.Context, message string) string {
	nonce, err := a.nonces.Generate(ctx)
	if err != nil {
		panic(err)
	}
	dat, err := json.Marshal(challengeMessage{
		Message: message,
		Nonce:   nonce,
	})
	if err != nil {
		panic(err)
	}
	return string(dat)
}

// Verify checks the signature and nonce.
//
// This is a time-based nonce. In production, it is preferable to use a true nonce (random number) which is stored in a database.
func (a *Auth) Verify(ctx context.Context, address string, data []byte, sig []byte) error {
	var hash []byte
	if sig[ethcrypto.RecoveryIDOffset] > 1 {
		// Legacy Keccak256
		// Transform yellow paper V from 27/28 to 0/1
		sig[ethcrypto.RecoveryIDOffset] -= 27
	}
	hash = accounts.TextHash(data)

	// Verify signature
	sigPublicKey, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		log.Err(err).
			Str("hash", hexutil.Encode(hash)).
			Str("sig", hexutil.Encode(sig)).
			Msg("SigToPub failed")
		return err
	}
	sigAddr := ethcrypto.PubkeyToAddress(*sigPublicKey)

	// Verify public key
	if !strings.EqualFold(address, sigAddr.Hex()) {
		log.Error().
			Str("sig.Address", sigAddr.Hex()).
			Str("address", address).
			Str("sig", hexutil.Encode(sig)).
			Str("expected hash", hexutil.Encode(hash)).
			Msg("addresses are not equal")
		return errors.New("authentication error: addresses are not equal")
	}

	// Verify message
	var msg challengeMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Err(err).
			Str("data", string(data)).
			Msg("invalid msg")
		return fmt.Errorf("authentication error: invalid msg: %w", err)
	}
	ok, err := a.nonces.IsValid(ctx, msg.Nonce)
	if err != nil {
		log.Err(err).
			Str("data", string(data)).
			Msg("nonce failure")
		return fmt.Errorf("authentication error: nonce failure: %w", err)
	}
	if !ok {
		log.Error().
			Str("data", string(data)).
			Msg("nonce failed verification")
		return errors.New("authentication error: nonce failed verification")
	}

	return nil
}
