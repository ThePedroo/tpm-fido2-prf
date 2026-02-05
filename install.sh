#!/bin/bash
#
# Installation script for tpm-fido2 as a systemd (or others) service.

set -e

# Variables
SERVICE_NAME="tpm-fido2"
BINARY_PATH="./tpm-fido"
BINARY_GLOBAL_PATH="${HOME}/.local/bin/${SERVICE_NAME}"

# INFO: Identify if the current system is using systemd
if pidof systemd &>/dev/null; then
  echo "- Detected systemd as the init system."

  # INFO: Move the binary to the global binary path
  mkdir -p "$(dirname "${BINARY_GLOBAL_PATH}")"
  mkdir -p "${HOME}/.config/systemd/user"
  if [ -f "${BINARY_PATH}" ]; then
    mv -f "${BINARY_PATH}" "${BINARY_GLOBAL_PATH}"
    chmod 0755 "${BINARY_GLOBAL_PATH}"
    echo "- Installed binary to ${BINARY_GLOBAL_PATH}"
  else
    echo "! Binary not found at '${BINARY_PATH}'."
    exit 1
  fi

  UNIT_PATH="${HOME}/.config/systemd/user/${SERVICE_NAME}.service"

  # INFO: Write the service file to the systemd directory
  cat > "${UNIT_PATH}" <<UNIT
[Unit]
Description=TPM-based FIDO2 Authenticator Service
After=network.target

[Service]
Type=simple
ExecStart=${BINARY_GLOBAL_PATH}
Restart=on-failure

[Install]
WantedBy=default.target
UNIT

  # INFO: Ensure unit file permissions are correct
  chmod 0644 "${UNIT_PATH}"

  # INFO: Reload systemd to recognize the new service and enable it (user mode)
  systemctl --user daemon-reload
  systemctl --user enable "${SERVICE_NAME}.service"
  systemctl --user start "${SERVICE_NAME}.service"

  echo "- Service unit written to ${UNIT_PATH} and enabled (will start on boot)."

else
  echo "! Your system does not appear to be using systemd. This installer currently only supports systemd."

  exit 0
fi
