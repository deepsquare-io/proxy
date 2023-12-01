// Package api is used to standardize SSH communications.
package api

// IDRequest is used to send a JWT token.
type IDRequest struct {
	ID string
}

// ChannelForwardRequest follows RFC 4254 7.1.
type ChannelForwardRequest struct {
	Addr  string
	RPort uint32
}

// ChannelForwardReply follows RFC 4254 7.1.
type ChannelForwardReply struct {
	Port uint32
}

// ForwardedTCPPayload follows RFC 4254 7.2.
type ForwardedTCPPayload struct {
	Addr       string // Connected to
	Port       uint32
	OriginAddr string
	OriginPort uint32
}
