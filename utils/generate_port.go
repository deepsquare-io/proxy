package utils

import (
	"math/rand"

	"github.com/google/uuid"
)

const minPort = 30001
const maxPort = 60000

const safeMinPort = 60001
const safeMaxPort = 65535

// GenerateRandomPort generates a random port in a range.
func GenerateRandomPort() int64 {
	return rand.Int63n(maxPort-minPort+1) + minPort
}

// GenerateSafeRandomPort generates a random port in a safe range.
func GenerateSafeRandomPort() int64 {
	return rand.Int63n(safeMaxPort-safeMinPort+1) + safeMinPort
}

// GenerateSubdomain generates a random subdomain
func GenerateSubdomain() string {
	return uuid.NewString()
}
