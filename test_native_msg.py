#!/usr/bin/env python3
"""Test script for tpm-fido Native Messaging protocol."""

import json
import struct
import subprocess
import sys
import base64
import os

def send_message(proc, msg):
    """Send a Native Messaging message to the process."""
    data = json.dumps(msg).encode('utf-8')
    length = struct.pack('<I', len(data))
    proc.stdin.write(length + data)
    proc.stdin.flush()

def read_message(proc):
    """Read a Native Messaging message from the process."""
    length_bytes = proc.stdout.read(4)
    if len(length_bytes) < 4:
        return None
    length = struct.unpack('<I', length_bytes)[0]
    data = proc.stdout.read(length)
    return json.loads(data.decode('utf-8'))

def main():
    # Start tpmfido with memory backend (no fingerprint prompt)
    # Note: In a real test, we'd need to handle the fingerprint prompt
    print("Starting tpmfido with memory backend...")

    # Create a test request
    challenge = base64.b64encode(os.urandom(32)).decode('utf-8')
    user_id = base64.b64encode(os.urandom(16)).decode('utf-8')

    create_request = {
        "type": "create",
        "requestId": "test-123",
        "origin": "https://example.com",
        "options": {
            "challenge": challenge,
            "rp": {
                "id": "example.com",
                "name": "Example"
            },
            "user": {
                "id": user_id,
                "name": "test@example.com",
                "displayName": "Test User"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7}
            ],
            "authenticatorSelection": {
                "residentKey": "required"
            },
            "extensions": {
                "prf": {
                    "eval": {
                        "first": base64.b64encode(os.urandom(32)).decode('utf-8')
                    }
                }
            }
        }
    }

    print(f"Test request: {json.dumps(create_request, indent=2)}")
    print("\nNote: This test will wait for fingerprint verification.")
    print("To test without fingerprint, you need fprintd-verify to succeed.")
    print("\nTo run the test:")
    print("  ./tpmfido --backend=memory")
    print("\nThen paste the request above (as a Native Messaging message)")

if __name__ == "__main__":
    main()
