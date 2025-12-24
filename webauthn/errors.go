package webauthn

import "errors"

// DOMException names for WebAuthn errors
const (
	ErrNameNotAllowed   = "NotAllowedError"
	ErrNameInvalidState = "InvalidStateError"
	ErrNameTypeError    = "TypeError"
	ErrNameUnknown      = "UnknownError"
)

// Common error conditions
var (
	ErrUserDenied          = errors.New("user denied the request")
	ErrTimeout             = errors.New("operation timed out")
	ErrNoCredentials       = errors.New("no credentials found")
	ErrCredentialExcluded  = errors.New("credential already registered")
	ErrInvalidParameters   = errors.New("invalid parameters")
	ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
)

// NewErrorResponse creates an ErrorResponse for the given request type and error.
func NewErrorResponse(reqType, requestID string, name, message string) *ErrorResponse {
	return &ErrorResponse{
		Type:      reqType,
		RequestID: requestID,
		Success:   false,
		Error: WebAuthnError{
			Name:    name,
			Message: message,
		},
	}
}

// MapErrorToResponse maps an internal error to a WebAuthn ErrorResponse.
func MapErrorToResponse(reqType, requestID string, err error) *ErrorResponse {
	name := ErrNameUnknown
	message := err.Error()

	switch {
	case errors.Is(err, ErrUserDenied):
		name = ErrNameNotAllowed
		message = "User denied the request"
	case errors.Is(err, ErrTimeout):
		name = ErrNameNotAllowed
		message = "Operation timed out"
	case errors.Is(err, ErrNoCredentials):
		name = ErrNameNotAllowed
		message = "No credentials found"
	case errors.Is(err, ErrCredentialExcluded):
		name = ErrNameInvalidState
		message = "Credential already registered"
	case errors.Is(err, ErrInvalidParameters):
		name = ErrNameTypeError
		message = "Invalid parameters"
	case errors.Is(err, ErrUnsupportedAlgorithm):
		name = ErrNameTypeError
		message = "Unsupported algorithm"
	}

	return NewErrorResponse(reqType, requestID, name, message)
}
