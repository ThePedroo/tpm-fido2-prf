// Package webauthn provides high-level WebAuthn request/response handling
// for the Native Messaging protocol.
package webauthn

// CreateOptions represents the options for navigator.credentials.create()
type CreateOptions struct {
	Challenge              string                  `json:"challenge"` // base64
	RP                     RelyingParty            `json:"rp"`
	User                   User                    `json:"user"`
	PubKeyCredParams       []PubKeyCredParam       `json:"pubKeyCredParams"`
	Timeout                int                     `json:"timeout,omitempty"`
	ExcludeCredentials     []CredentialDescriptor  `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection *AuthenticatorSelection `json:"authenticatorSelection,omitempty"`
	Extensions             *CreateExtensions       `json:"extensions,omitempty"`
}

// GetOptions represents the options for navigator.credentials.get()
type GetOptions struct {
	Challenge        string                 `json:"challenge"` // base64
	RPID             string                 `json:"rpId"`
	Timeout          int                    `json:"timeout,omitempty"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials,omitempty"`
	UserVerification string                 `json:"userVerification,omitempty"`
	Extensions       *GetExtensions         `json:"extensions,omitempty"`
}

// RelyingParty represents the relying party information
type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// User represents user account information
type User struct {
	ID          string `json:"id"` // base64
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// PubKeyCredParam represents a supported public key algorithm
type PubKeyCredParam struct {
	Type string `json:"type"` // always "public-key"
	Alg  int    `json:"alg"`  // -7 for ES256, -257 for RS256
}

// CredentialDescriptor identifies a credential
type CredentialDescriptor struct {
	Type string `json:"type"` // always "public-key"
	ID   string `json:"id"`   // base64
}

// AuthenticatorSelection specifies authenticator requirements
type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

// CreateExtensions represents extensions for create requests
type CreateExtensions struct {
	PRF *PRFExtension `json:"prf,omitempty"`
}

// GetExtensions represents extensions for get requests
type GetExtensions struct {
	PRF *PRFExtension `json:"prf,omitempty"`
}

// PRFExtension represents the PRF extension input
type PRFExtension struct {
	Eval *PRFEval `json:"eval,omitempty"`
}

// PRFEval represents PRF evaluation parameters
type PRFEval struct {
	First  string `json:"first"`            // base64, 32 bytes salt
	Second string `json:"second,omitempty"` // base64, 32 bytes salt (optional)
}

// CreateResponse is the response for a create request
type CreateResponse struct {
	Type       string      `json:"type"`      // "create"
	RequestID  string      `json:"requestId"` // echoed from request
	Success    bool        `json:"success"`
	Credential *Credential `json:"credential,omitempty"`
}

// GetResponse is the response for a get request
type GetResponse struct {
	Type       string      `json:"type"`      // "get"
	RequestID  string      `json:"requestId"` // echoed from request
	Success    bool        `json:"success"`
	Credential *Credential `json:"credential,omitempty"`
}

// Credential represents the credential in responses
type Credential struct {
	ID                      string                 `json:"id"`   // base64url
	RawID                   string                 `json:"rawId"` // base64
	Type                    string                 `json:"type"` // "public-key"
	AuthenticatorAttachment string                 `json:"authenticatorAttachment"` // "platform"
	Response                interface{}            `json:"response"`
	ClientExtensionResults  ClientExtensionResults `json:"clientExtensionResults"`
}

// AttestationResponse is the response data for credential creation
type AttestationResponse struct {
	ClientDataJSON    string   `json:"clientDataJSON"`    // base64
	AttestationObject string   `json:"attestationObject"` // base64
	Transports        []string `json:"transports"`
}

// AssertionResponse is the response data for authentication
type AssertionResponse struct {
	ClientDataJSON    string  `json:"clientDataJSON"`    // base64
	AuthenticatorData string  `json:"authenticatorData"` // base64
	Signature         string  `json:"signature"`         // base64
	UserHandle        *string `json:"userHandle"`        // base64, nullable
}

// ClientExtensionResults contains extension outputs
type ClientExtensionResults struct {
	PRF *PRFResult `json:"prf,omitempty"`
}

// PRFResult is the PRF extension output
type PRFResult struct {
	Enabled bool        `json:"enabled,omitempty"`
	Results *PRFOutputs `json:"results,omitempty"`
}

// PRFOutputs contains the PRF HMAC outputs
type PRFOutputs struct {
	First  string `json:"first,omitempty"`  // base64, 32 bytes
	Second string `json:"second,omitempty"` // base64, 32 bytes
}

// ErrorResponse is returned when an operation fails
type ErrorResponse struct {
	Type      string       `json:"type"`      // "create" or "get"
	RequestID string       `json:"requestId"` // echoed from request
	Success   bool         `json:"success"`   // always false
	Error     WebAuthnError `json:"error"`
}

// WebAuthnError represents a WebAuthn DOMException
type WebAuthnError struct {
	Name    string `json:"name"`    // DOMException name
	Message string `json:"message"` // Human-readable message
}
