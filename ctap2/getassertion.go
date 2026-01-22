package ctap2

import (
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/psanford/tpm-fido/storage"
)

// GetAssertion handles the authenticatorGetAssertion command
func (h *Handler) GetAssertion(ctx context.Context, req *GetAssertionRequest) (byte, []byte) {
	log.Printf("CTAP2 GetAssertion: RPID=%s, allowList=%d credentials", req.RPID, len(req.AllowList))

	// Validate clientDataHash
	if len(req.ClientDataHash) != 32 {
		log.Printf("CTAP2 GetAssertion: Invalid clientDataHash length: %d", len(req.ClientDataHash))
		return StatusInvalidParameter, nil
	}

	// Compute rpIdHash
	rpIDHash := HashRPID(req.RPID)

	// Find a valid credential from the allowList
	var matchedCredential *PublicKeyCredentialDescriptor
	for i := range req.AllowList {
		cred := &req.AllowList[i]

		// Ask the signer to validate the key handle format before attempting heavy work.
		if err := h.signer.ValidateKeyHandle(cred.ID); err != nil {
			log.Printf("CTAP2 GetAssertion: skipping credential len=%d; not our key handle: %v", len(cred.ID), err)

			continue
		}

		// Try to sign with a dummy hash to check if credential is valid
		dummyHash := sha256.Sum256([]byte("credential-check"))
		_, err := h.signer.SignASN1(cred.ID, rpIDHash[:], dummyHash[:])
		if err == nil {
			matchedCredential = cred
			log.Printf("CTAP2 GetAssertion: Found valid credential, ID length=%d", len(cred.ID))
			break
		} else {
			idSum := sha256.Sum256(cred.ID)

			log.Printf("CTAP2 GetAssertion: credential check failed for ID len=%d, SHA256=%x: %v", len(cred.ID), idSum, err)
		}
	}

	if matchedCredential == nil {
		log.Printf("CTAP2 GetAssertion: No valid credential found in allowList; attempting stored credentials for RP=%s", req.RPID)
		stored, err := storage.GetCredentialsForRPID(req.RPID)
		if err != nil {
			log.Printf("CTAP2 GetAssertion: error reading stored credentials: %v", err)
			return StatusNoCredentials, nil
		}

		for _, c := range stored {
			log.Printf("CTAP2 GetAssertion: trying stored credential len=%d", len(c))

			dummyHash := sha256.Sum256([]byte("credential-check"))
			if _, err := h.signer.SignASN1(c, rpIDHash[:], dummyHash[:]); err == nil {
				matchedCredential = &PublicKeyCredentialDescriptor{Type: CredentialTypePublicKey, ID: c}

				log.Printf("CTAP2 GetAssertion: Found valid stored credential, ID length=%d", len(c))

				break
			} else {
				log.Printf("CTAP2 GetAssertion: stored credential failed: %v", err)
			}
		}

		if matchedCredential == nil {
			log.Printf("CTAP2 GetAssertion: No stored credential matched")

			return StatusNoCredentials, nil
		}
	}

	// Request user presence
	var challengeParam, appParam [32]byte
	copy(challengeParam[:], req.ClientDataHash)
	copy(appParam[:], rpIDHash[:])

	pinResultCh, err := h.presence.ConfirmPresence("FIDO2 Confirm Auth", challengeParam, appParam)
	if err != nil {
		log.Printf("CTAP2 GetAssertion: user presence error: %s", err)
		return StatusOperationDenied, nil
	}

	// Wait for user response with timeout
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	select {
	case result := <-pinResultCh:
		if !result.OK {
			log.Printf("CTAP2 GetAssertion: User denied or error: %v", result.Error)
			return StatusOperationDenied, nil
		}
	case <-childCtx.Done():
		log.Printf("CTAP2 GetAssertion: User presence timeout")
		return StatusUserActionTimeout, nil
	}

	// Process hmac-secret extension if present
	var extensionsOutput []byte
	log.Printf("CTAP2 GetAssertion: Extensions=%+v", req.Extensions)
	if req.Extensions != nil {
		for k, v := range req.Extensions {
			log.Printf("CTAP2 GetAssertion: Extension key=%q, value type=%T", k, v)
		}
		if hmacSecretInput, ok := req.Extensions["hmac-secret"]; ok {
			log.Printf("CTAP2 GetAssertion: Processing hmac-secret extension")
			hmacOutput, err := h.processHmacSecret(matchedCredential.ID, hmacSecretInput)
			if err != nil {
				log.Printf("CTAP2 GetAssertion: hmac-secret error: %s", err)
				return StatusExtensionFirst, nil
			}
			extMap := map[string][]byte{"hmac-secret": hmacOutput}
			extensionsOutput, _ = ctapEncMode.Marshal(extMap)
		}
	}

	// Build flags
	flags := byte(FlagUserPresent | FlagUserVerified)
	if len(extensionsOutput) > 0 {
		flags |= FlagExtensionData
	}

	// Build AuthenticatorData (no attested credential data for assertion)
	authData := &AuthenticatorData{
		RPIDHash:   rpIDHash,
		Flags:      flags,
		SignCount:  h.signer.Counter(),
		Extensions: extensionsOutput,
	}

	authDataBytes := authData.Marshal()

	// Sign authData || clientDataHash
	toSign := append(authDataBytes, req.ClientDataHash...)
	sigHash := sha256.Sum256(toSign)

	sig, err := h.signer.SignASN1(matchedCredential.ID, rpIDHash[:], sigHash[:])
	if err != nil {
		log.Printf("CTAP2 GetAssertion: Sign error: %s", err)
		return StatusOther, nil
	}

	// Build response
	resp := &GetAssertionResponse{
		Credential: &PublicKeyCredentialDescriptor{
			Type: CredentialTypePublicKey,
			ID:   matchedCredential.ID,
		},
		AuthData:  authDataBytes,
		Signature: sig,
	}

	encoded, err := ctapEncMode.Marshal(resp)
	if err != nil {
		log.Printf("CTAP2 GetAssertion: Response encode error: %s", err)
		return StatusOther, nil
	}

	log.Printf("CTAP2 GetAssertion: Success, response=%d bytes", len(encoded))
	return StatusSuccess, encoded
}

// parseGetAssertionRequest parses the CBOR-encoded GetAssertion request
func parseGetAssertionRequest(data []byte) (*GetAssertionRequest, error) {
	var req GetAssertionRequest
	if err := cbor.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}
