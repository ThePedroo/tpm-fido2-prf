package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/psanford/tpm-fido/ctap2"
	"github.com/psanford/tpm-fido/memory"
	"github.com/psanford/tpm-fido/nativemsg"
	"github.com/psanford/tpm-fido/tpm"
	"github.com/psanford/tpm-fido/userpresence"
	"github.com/psanford/tpm-fido/webauthn"
)

var (
	backend = flag.String("backend", "tpm", "Backend to use: tpm or memory")
	device  = flag.String("device", "/dev/tpmrm0", "TPM device path")
)

func main() {
	flag.Parse()

	// Set up logging to stderr (Native Messaging uses stdout for communication)
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("tpm-fido starting with backend=%s", *backend)

	// Initialize the signer backend
	var signer ctap2.Signer
	var err error

	switch *backend {
	case "tpm":
		signer, err = tpm.New(*device)
		if err != nil {
			log.Fatalf("Failed to initialize TPM backend: %v", err)
		}
		log.Printf("TPM backend initialized using %s", *device)
	case "memory":
		signer, err = memory.New()
		if err != nil {
			log.Fatalf("Failed to initialize memory backend: %v", err)
		}
		log.Printf("Memory backend initialized (for testing only)")
	default:
		log.Fatalf("Unknown backend: %s (use 'tpm' or 'memory')", *backend)
	}

	// Initialize user presence handler
	presence := userpresence.New()
	log.Printf("User presence handler initialized")

	// Initialize credential storage for resident keys
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}
	storagePath := filepath.Join(homeDir, ".local", "share", "tpm-fido", "credentials.json")
	storage, err := ctap2.NewCredentialStorage(storagePath)
	if err != nil {
		log.Fatalf("Failed to create credential storage: %v", err)
	}
	log.Printf("Credential storage initialized at %s (%d credentials)", storagePath, storage.Count())

	// Create CTAP2 handler
	ctap2Handler := ctap2.NewHandler(signer, presence, storage)
	log.Printf("CTAP2 handler initialized")

	// Create WebAuthn handler
	handler := webauthn.NewHandler(ctap2Handler)
	log.Printf("WebAuthn handler initialized")

	// Run the Native Messaging loop
	ctx := context.Background()
	runNativeMessaging(ctx, handler)
}

// runNativeMessaging runs the Native Messaging I/O loop
func runNativeMessaging(ctx context.Context, handler *webauthn.Handler) {
	log.Printf("Starting Native Messaging loop")

	for {
		// Read request from stdin
		msg, err := nativemsg.Read(os.Stdin)
		if err != nil {
			if err == io.EOF {
				log.Printf("Extension closed connection (EOF)")
				return
			}
			log.Printf("Read error: %v", err)
			return
		}

		log.Printf("Received message: %d bytes", len(msg))

		// Handle the request
		response := handler.HandleRequest(ctx, msg)

		// Write response to stdout
		if err := nativemsg.Write(os.Stdout, response); err != nil {
			log.Printf("Write error: %v", err)
			return
		}

		log.Printf("Response sent")
	}
}
