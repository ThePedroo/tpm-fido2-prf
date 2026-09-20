package pinentry

import (
	"testing"
	"time"
)

// Two callers sharing one prompt (same challenge + app) must both observe
// the result. Uses a short timeout so no human interaction is needed;
// whichever way the prompt resolves (timer or pinentry failure), the
// result must reach every subscriber and the slot must be released.
func TestConfirmPresenceBroadcast(t *testing.T) {
	pe := New()

	var challenge, app, otherApp [32]byte
	challenge[0] = 1
	otherApp[0] = 2

	first, err := pe.ConfirmPresence("test", challenge, app, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("first ConfirmPresence err: %s", err)
	}

	second, err := pe.ConfirmPresence("test", challenge, app, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("second ConfirmPresence err: %s", err)
	}

	if _, err := pe.ConfirmPresence("test", challenge, otherApp, 300*time.Millisecond); err == nil {
		t.Fatal("expected other-request-in-progress error for different params")
	}

	deadline := time.After(10 * time.Second)
	got := 0
	for got < 2 {
		select {
		case <-first:
			got++
			first = nil
		case <-second:
			got++
			second = nil
		case <-deadline:
			t.Fatalf("only %d/2 waiters received a result", got)
		}
		// nil out a received channel so we wait for the other one
		if first == nil && second == nil {
			break
		}
	}

	pe.mu.Lock()
	active := pe.activeRequest
	pe.mu.Unlock()
	if active != nil {
		t.Fatal("activeRequest not cleared after completion")
	}

	// A fresh prompt must be possible after the previous one completed.
	if _, err := pe.ConfirmPresence("test", challenge, app, 300*time.Millisecond); err != nil {
		t.Fatalf("ConfirmPresence after completion err: %s", err)
	}
}
