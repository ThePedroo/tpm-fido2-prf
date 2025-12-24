// Package nativemsg implements Chrome Native Messaging protocol I/O.
// Messages are length-prefixed JSON: 4 bytes little-endian length, then JSON payload.
package nativemsg

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// MaxMessageSize is the maximum allowed message size (1MB as per Chrome spec)
const MaxMessageSize = 1024 * 1024

// Read reads a single Native Messaging message from the reader.
// Returns the raw JSON message or an error.
func Read(r io.Reader) (json.RawMessage, error) {
	// Read 4-byte length prefix (little-endian)
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	// Validate length
	if length == 0 {
		return nil, fmt.Errorf("invalid message length: 0")
	}
	if length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, MaxMessageSize)
	}

	// Read the message payload
	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, fmt.Errorf("failed to read message payload: %w", err)
	}

	return json.RawMessage(msg), nil
}

// Write writes a single Native Messaging message to the writer.
// The message is JSON-encoded with a 4-byte little-endian length prefix.
func Write(w io.Writer, msg interface{}) error {
	// Marshal the message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Validate length
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", len(data), MaxMessageSize)
	}

	// Write 4-byte length prefix (little-endian)
	length := uint32(len(data))
	if err := binary.Write(w, binary.LittleEndian, length); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}

	// Write the message payload
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to write message payload: %w", err)
	}

	return nil
}
