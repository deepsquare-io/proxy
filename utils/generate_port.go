package utils

import "math/rand"

const minPort = 30001
const maxPort = 60000

const safeMinPort = 60001
const safeMaxPort = 65535

func GenerateRandomPort() int64 {
	return rand.Int63n(maxPort-minPort+1) + minPort
}

func GenerateSafeRandomPort() int64 {
	return rand.Int63n(safeMaxPort-safeMinPort+1) + safeMinPort
}

const subdomainLength = 10

func GenerateSubdomain() string {
	// Define the character set for the subdomain
	charSet := "abcdefghijklmnopqrstuvwxyz0123456789"

	// Generate a random subdomain of the specified length
	subdomain := make([]byte, subdomainLength)
	for i := range subdomain {
		subdomain[i] = charSet[rand.Intn(len(charSet))]
	}

	return string(subdomain)
}