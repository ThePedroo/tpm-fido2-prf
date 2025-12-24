# TPM-FIDO Native Messaging Protocol Specification

This document defines the JSON protocol between a Chrome browser extension and tpm-fido for WebAuthn platform authenticator functionality.

## Overview

tpm-fido acts as a Chrome Native Messaging host that provides WebAuthn platform authenticator capabilities using the system TPM for secure key storage. The extension intercepts `navigator.credentials.create()` and `navigator.credentials.get()` calls and proxies them to tpm-fido.

## Native Messaging Format

Chrome Native Messaging uses length-prefixed JSON:
- **Read**: 4 bytes little-endian length, then JSON payload
- **Write**: 4 bytes little-endian length, then JSON payload

Maximum message size: 1MB

## Request Envelope

All requests share this envelope structure:

```json
{
  "type": "create" | "get",
  "requestId": "uuid-string",
  "origin": "https://example.com",
  "options": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `"create"` or `"get"` |
| `requestId` | string | UUID echoed in response for request correlation |
| `origin` | string | Origin URL (e.g., `"https://confer.to"`) |
| `options` | object | CreateOptions or GetOptions |

## Create Request

For `navigator.credentials.create()`:

```json
{
  "type": "create",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "origin": "https://example.com",
  "options": {
    "challenge": "base64-encoded-challenge",
    "rp": {
      "id": "example.com",
      "name": "Example Site"
    },
    "user": {
      "id": "base64-encoded-user-id",
      "name": "user@example.com",
      "displayName": "User Name"
    },
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 }
    ],
    "timeout": 60000,
    "excludeCredentials": [
      { "type": "public-key", "id": "base64-credential-id" }
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "residentKey": "required",
      "userVerification": "required"
    },
    "extensions": {
      "prf": {
        "eval": {
          "first": "base64-32-byte-salt",
          "second": "base64-32-byte-salt-optional"
        }
      }
    }
  }
}
```

### CreateOptions Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `challenge` | string | Yes | Base64-encoded challenge bytes |
| `rp.id` | string | Yes | Relying party ID (domain) |
| `rp.name` | string | Yes | Human-readable RP name |
| `user.id` | string | Yes | Base64-encoded user handle |
| `user.name` | string | Yes | User account name |
| `user.displayName` | string | Yes | User display name |
| `pubKeyCredParams` | array | Yes | Supported algorithms (must include `-7` for ES256) |
| `timeout` | number | No | Timeout in milliseconds (default: 60000) |
| `excludeCredentials` | array | No | Credentials to exclude (prevent re-registration) |
| `authenticatorSelection.residentKey` | string | No | `"discouraged"`, `"preferred"`, or `"required"` |
| `authenticatorSelection.userVerification` | string | No | `"discouraged"`, `"preferred"`, or `"required"` |
| `extensions.prf.eval` | object | No | PRF evaluation during create |

### PRF During Create

When `extensions.prf.eval` is present, tpm-fido computes PRF outputs immediately after credential creation. This is a key feature for platform authenticators.

```json
"extensions": {
  "prf": {
    "eval": {
      "first": "base64-32-byte-salt",
      "second": "base64-32-byte-salt-optional"
    }
  }
}
```

## Get Request

For `navigator.credentials.get()`:

```json
{
  "type": "get",
  "requestId": "550e8400-e29b-41d4-a716-446655440001",
  "origin": "https://example.com",
  "options": {
    "challenge": "base64-encoded-challenge",
    "rpId": "example.com",
    "timeout": 60000,
    "allowCredentials": [
      { "type": "public-key", "id": "base64-credential-id" }
    ],
    "userVerification": "required"
  }
}
```

### GetOptions Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `challenge` | string | Yes | Base64-encoded challenge bytes |
| `rpId` | string | Yes | Relying party ID (domain) |
| `timeout` | number | No | Timeout in milliseconds (default: 60000) |
| `allowCredentials` | array | No | Allowed credentials (empty for discoverable) |
| `userVerification` | string | No | `"discouraged"`, `"preferred"`, or `"required"` |

### Discoverable Credentials

When `allowCredentials` is empty or omitted, tpm-fido performs discoverable credential lookup by rpId.

## Success Response (Create)

```json
{
  "type": "create",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "success": true,
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64-credential-id",
    "type": "public-key",
    "authenticatorAttachment": "platform",
    "response": {
      "clientDataJSON": "base64-client-data-json",
      "attestationObject": "base64-attestation-object",
      "transports": ["internal"]
    },
    "clientExtensionResults": {
      "prf": {
        "enabled": true,
        "results": {
          "first": "base64-32-byte-output",
          "second": "base64-32-byte-output-optional"
        }
      }
    }
  }
}
```

## Success Response (Get)

```json
{
  "type": "get",
  "requestId": "550e8400-e29b-41d4-a716-446655440001",
  "success": true,
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64-credential-id",
    "type": "public-key",
    "authenticatorAttachment": "platform",
    "response": {
      "clientDataJSON": "base64-client-data-json",
      "authenticatorData": "base64-authenticator-data",
      "signature": "base64-signature",
      "userHandle": "base64-user-handle-or-null"
    },
    "clientExtensionResults": {
      "prf": {
        "results": {
          "first": "base64-32-byte-output",
          "second": "base64-32-byte-output-optional"
        }
      }
    }
  }
}
```

## Error Response

```json
{
  "type": "create",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "success": false,
  "error": {
    "name": "NotAllowedError",
    "message": "User denied the request"
  }
}
```

### DOMException Error Names

| Condition | `error.name` | Description |
|-----------|--------------|-------------|
| User denied fingerprint | `NotAllowedError` | User rejected the authentication |
| Fingerprint timeout | `NotAllowedError` | Operation timed out |
| No matching credential | `NotAllowedError` | No credentials found for site |
| Credential in excludeList | `InvalidStateError` | Credential already registered |
| Invalid parameters | `TypeError` | Malformed request |
| Internal error | `UnknownError` | Unexpected error |

## clientDataJSON Format

tpm-fido constructs the `clientDataJSON` internally:

```json
{
  "type": "webauthn.create",
  "challenge": "base64url-challenge",
  "origin": "https://example.com",
  "crossOrigin": false
}
```

For get operations, `type` is `"webauthn.get"`.

## Installation

### Native Messaging Host Manifest

Create `/etc/opt/chrome/native-messaging-hosts/com.vitorpy.tpmfido.json`:

```json
{
  "name": "com.vitorpy.tpmfido",
  "description": "TPM-FIDO WebAuthn Platform Authenticator",
  "path": "/usr/local/bin/tpmfido",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://YOUR_EXTENSION_ID/"
  ]
}
```

### User Installation

For user-level installation, place the manifest at:
`~/.config/google-chrome/NativeMessagingHosts/com.vitorpy.tpmfido.json`

## Extension Implementation Notes

1. **Intercept WebAuthn calls**: Use `window.navigator.credentials` polyfill or content script injection
2. **Connect to native host**: `chrome.runtime.connectNative("com.vitorpy.tpmfido")`
3. **Handle `platform` attachment**: Return tpm-fido responses for platform authenticator requests
4. **PRF during create**: Forward `extensions.prf.eval` to get immediate PRF outputs
5. **Base64 encoding**: All binary data uses standard Base64, except `credential.id` which uses Base64URL

## Algorithm Support

- **ES256** (COSE algorithm -7): ECDSA with P-256 and SHA-256

## Transports

- **internal**: Platform authenticator transport

## Example Extension Flow

### Create Credential

```javascript
// 1. Extension intercepts navigator.credentials.create()
const publicKey = { /* WebAuthn options */ };

// 2. Build native message
const message = {
  type: "create",
  requestId: crypto.randomUUID(),
  origin: window.location.origin,
  options: {
    challenge: base64Encode(publicKey.challenge),
    rp: publicKey.rp,
    user: {
      id: base64Encode(publicKey.user.id),
      name: publicKey.user.name,
      displayName: publicKey.user.displayName
    },
    pubKeyCredParams: publicKey.pubKeyCredParams,
    extensions: publicKey.extensions
  }
};

// 3. Send to native host
const response = await sendNativeMessage("com.vitorpy.tpmfido", message);

// 4. Convert response to PublicKeyCredential
if (response.success) {
  return buildPublicKeyCredential(response.credential);
} else {
  throw new DOMException(response.error.message, response.error.name);
}
```

## Security Considerations

1. **TPM-backed keys**: Private keys never leave the TPM
2. **User presence**: Fingerprint verification required for all operations
3. **Origin binding**: Credentials are bound to the RP ID (domain)
4. **Extension validation**: Only allowed extension IDs can connect

## Credential Storage

Resident credentials are stored at:
`~/.local/share/tpm-fido/credentials.json`

This file contains credential metadata only (user info, RP info, credential ID). Private keys remain in the TPM.
