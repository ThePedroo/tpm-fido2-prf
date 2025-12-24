# tpm-fido

tpm-fido is a FIDO2/WebAuthn platform authenticator for Linux that protects credential keys using your system's TPM (Trusted Platform Module). It works with Chrome/Chromium via Native Messaging and supports the PRF (Pseudo-Random Function) extension for deriving cryptographic material from credentials.

## Features

- **TPM-backed keys**: Private keys never leave the TPM
- **Fingerprint verification**: User presence via fprintd
- **PRF extension support**: Derive encryption keys from credentials (works during create and get)
- **Resident keys**: Discoverable credentials stored locally
- **Platform authenticator**: Presents as a built-in authenticator to websites

## Implementation Details

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration, tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 20 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 20 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 20 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

## Prerequisites

1. **TPM access**: Your user must have permission to access `/dev/tpmrm0`
   ```bash
   sudo usermod -aG tss $USER
   # Log out and back in for group changes to take effect
   ```

2. **Fingerprint enrollment**: Enroll at least one fingerprint via fprintd
   ```bash
   fprintd-enroll
   ```

3. **Go compiler**: Required to build from source
   ```bash
   # Arch Linux
   sudo pacman -S go

   # Ubuntu/Debian
   sudo apt install golang
   ```

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/vitorpy/tpm-fido2-prf.git
   cd tpm-fido2-prf
   ```

2. **Load the Chrome extension**
   - Open Chrome and navigate to `chrome://extensions`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `tpm-fido2-extension` directory
   - Copy the extension ID (32-character string shown below the extension name)

3. **Run the install script**
   ```bash
   ./contrib/install.sh <extension-id>
   ```

   This will:
   - Build the `tpm-fido` binary
   - Install it to `~/bin/tpm-fido`
   - Configure the Native Messaging manifest for Chrome/Chromium

4. **Restart Chrome** to pick up the Native Messaging host

## Testing

1. Visit [webauthn.io](https://webauthn.io) to test basic registration and authentication
2. Check the extension's service worker console for debug logs:
   - Go to `chrome://extensions`
   - Find "TPM-FIDO2 Platform Authenticator"
   - Click "Inspect views: service worker"

## Credential Storage

Resident credential metadata is stored at:
```
~/.local/share/tpm-fido/credentials.json
```

This file contains credential metadata only (user info, RP info, credential ID). Private keys remain in the TPM and are never stored on disk.

## Protocol

For details on the Native Messaging protocol between the Chrome extension and tpm-fido, see [docs/EXTENSION_PROTOCOL.md](docs/EXTENSION_PROTOCOL.md).

## Dependencies

- `pinentry`: For fingerprint verification prompts (usually installed with GPG)
- `fprintd`: For fingerprint authentication

## Troubleshooting

### "Native host has exited"
- Verify the native messaging manifest is installed correctly:
  ```bash
  cat ~/.config/google-chrome/NativeMessagingHosts/com.vitorpy.tpmfido.json
  ```
- Check that the binary path in the manifest points to an existing executable
- Check that the extension ID in the manifest matches your loaded extension

### "Permission denied" on /dev/tpmrm0
- Add your user to the `tss` group:
  ```bash
  sudo usermod -aG tss $USER
  ```
- Log out and back in for group changes to take effect

### Fingerprint not working
- Ensure fingerprints are enrolled: `fprintd-list $USER`
- Enroll a fingerprint: `fprintd-enroll`

## License

See [LICENSE](LICENSE) file.
