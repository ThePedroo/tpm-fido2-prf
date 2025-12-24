package webauthn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// ClientDataType constants for WebAuthn operations
const (
	ClientDataTypeCreate = "webauthn.create"
	ClientDataTypeGet    = "webauthn.get"
)

// CollectedClientData represents the clientDataJSON structure
type CollectedClientData struct {
	Type        string `json:"type"`        // "webauthn.create" or "webauthn.get"
	Challenge   string `json:"challenge"`   // base64url-encoded challenge
	Origin      string `json:"origin"`      // e.g., "https://confer.to"
	CrossOrigin bool   `json:"crossOrigin"` // always false for our use case
}

// BuildClientDataJSON constructs the clientDataJSON bytes.
// typ should be ClientDataTypeCreate or ClientDataTypeGet.
// challenge is the raw challenge bytes.
// origin is the origin URL.
func BuildClientDataJSON(typ string, challenge []byte, origin string) ([]byte, error) {
	clientData := CollectedClientData{
		Type:        typ,
		Challenge:   base64.RawURLEncoding.EncodeToString(challenge),
		Origin:      origin,
		CrossOrigin: false,
	}
	return json.Marshal(clientData)
}

// ClientDataHash computes the SHA-256 hash of clientDataJSON.
// This is used for signing in WebAuthn operations.
func ClientDataHash(clientDataJSON []byte) [32]byte {
	return sha256.Sum256(clientDataJSON)
}
