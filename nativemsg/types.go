package nativemsg

import "encoding/json"

// RequestEnvelope is the common envelope for all incoming requests.
type RequestEnvelope struct {
	Type      string          `json:"type"`      // "create" or "get"
	RequestID string          `json:"requestId"` // UUID echoed in response
	Origin    string          `json:"origin"`    // e.g., "https://confer.to"
	Options   json.RawMessage `json:"options"`   // CreateOptions or GetOptions
}
