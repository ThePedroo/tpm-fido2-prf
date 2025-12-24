package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestBuildClientDataJSON(t *testing.T) {
	challenge := []byte("test-challenge-bytes")
	origin := "https://example.com"

	// Test create type
	createData, err := BuildClientDataJSON(ClientDataTypeCreate, challenge, origin)
	if err != nil {
		t.Fatalf("BuildClientDataJSON failed: %v", err)
	}

	var createParsed CollectedClientData
	if err := json.Unmarshal(createData, &createParsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if createParsed.Type != "webauthn.create" {
		t.Errorf("Expected type=webauthn.create, got %s", createParsed.Type)
	}
	if createParsed.Origin != origin {
		t.Errorf("Expected origin=%s, got %s", origin, createParsed.Origin)
	}
	if createParsed.CrossOrigin != false {
		t.Errorf("Expected crossOrigin=false, got %v", createParsed.CrossOrigin)
	}

	// Verify challenge is base64url encoded
	decodedChallenge, err := base64.RawURLEncoding.DecodeString(createParsed.Challenge)
	if err != nil {
		t.Fatalf("Failed to decode challenge: %v", err)
	}
	if string(decodedChallenge) != string(challenge) {
		t.Errorf("Challenge mismatch: got %s, want %s", decodedChallenge, challenge)
	}

	// Test get type
	getData, err := BuildClientDataJSON(ClientDataTypeGet, challenge, origin)
	if err != nil {
		t.Fatalf("BuildClientDataJSON failed: %v", err)
	}

	var getParsed CollectedClientData
	if err := json.Unmarshal(getData, &getParsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if getParsed.Type != "webauthn.get" {
		t.Errorf("Expected type=webauthn.get, got %s", getParsed.Type)
	}
}

func TestClientDataHash(t *testing.T) {
	clientData := []byte(`{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com","crossOrigin":false}`)
	hash := ClientDataHash(clientData)

	// Hash should be 32 bytes (SHA-256)
	if len(hash) != 32 {
		t.Errorf("Expected hash length 32, got %d", len(hash))
	}

	// Same input should produce same hash
	hash2 := ClientDataHash(clientData)
	if hash != hash2 {
		t.Error("Hash not deterministic")
	}
}
