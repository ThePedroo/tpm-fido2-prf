package nativemsg

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestReadWrite(t *testing.T) {
	// Test message
	msg := map[string]interface{}{
		"type":      "create",
		"requestId": "test-123",
		"origin":    "https://example.com",
	}

	// Write to buffer
	var buf bytes.Buffer
	if err := Write(&buf, msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read from buffer
	result, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Parse and verify
	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed["type"] != "create" {
		t.Errorf("Expected type=create, got %v", parsed["type"])
	}
	if parsed["requestId"] != "test-123" {
		t.Errorf("Expected requestId=test-123, got %v", parsed["requestId"])
	}
	if parsed["origin"] != "https://example.com" {
		t.Errorf("Expected origin=https://example.com, got %v", parsed["origin"])
	}
}

func TestReadWriteRoundTrip(t *testing.T) {
	// Test with complex message
	msg := RequestEnvelope{
		Type:      "create",
		RequestID: "uuid-12345",
		Origin:    "https://confer.to",
		Options:   json.RawMessage(`{"challenge":"dGVzdA=="}`),
	}

	// Write
	var buf bytes.Buffer
	if err := Write(&buf, msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read
	result, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Parse
	var parsed RequestEnvelope
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.Type != msg.Type {
		t.Errorf("Type mismatch: got %s, want %s", parsed.Type, msg.Type)
	}
	if parsed.RequestID != msg.RequestID {
		t.Errorf("RequestID mismatch: got %s, want %s", parsed.RequestID, msg.RequestID)
	}
	if parsed.Origin != msg.Origin {
		t.Errorf("Origin mismatch: got %s, want %s", parsed.Origin, msg.Origin)
	}
}

func TestReadEmptyMessage(t *testing.T) {
	// Create a message with length 0
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 0}) // Length = 0

	_, err := Read(&buf)
	if err == nil {
		t.Error("Expected error for empty message")
	}
}

func TestReadTooLargeMessage(t *testing.T) {
	// Create a message with length > MaxMessageSize
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x00, 0x10, 0x00}) // Length = 1MB + 1

	_, err := Read(&buf)
	if err == nil {
		t.Error("Expected error for too large message")
	}
}
