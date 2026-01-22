package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var mu sync.Mutex

func storePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".local", "share", "tpm-fido")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func SaveCredential(rpID string, credID []byte) error {
	mu.Lock()
	defer mu.Unlock()

	p, err := storePath()
	if err != nil {
		return err
	}

	m := map[string][]string{}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &m)
	}

	enc := base64.RawURLEncoding.EncodeToString(credID)

	list := m[rpID]
	for _, s := range list {
		if s == enc {
			return nil
		}
	}

	m[rpID] = append(list, enc)

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(p, b, 0600); err != nil {
		return fmt.Errorf("write store: %w", err)
	}

	return nil
}

func GetCredentialsForRPID(rpID string) ([][]byte, error) {
	mu.Lock()
	defer mu.Unlock()

	p, err := storePath()
	if err != nil {
		return nil, err
	}

	m := map[string][]string{}
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	out := [][]byte{}
	for _, s := range m[rpID] {
		if data, err := base64.RawURLEncoding.DecodeString(s); err == nil {
			out = append(out, data)
		}
	}
	return out, nil
}
