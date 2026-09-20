package tpm

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/psanford/tpm-fido/internal/lencode"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	saltSizeBytes = 32
	curveOrder    = elliptic.P256().Params().N
	halfOrder     = new(big.Int).Rsh(curveOrder, 1)
)

type TPM struct {
	devicePath string
	mu         sync.Mutex
}

func (t *TPM) open() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(t.devicePath)
}

func New(devicePath string) (*TPM, error) {
	t := &TPM{devicePath: devicePath}
	tpm, err := t.open()
	if err != nil {
		return nil, err
	}
	tpm.Close()
	return t, nil
}

// deriveECPoint deterministically generates a 64-byte NIST P-256 unique point from a salt and label.
func deriveECPoint(salt, info []byte) tpm2.ECPoint {
	r := hkdf.New(sha256.New, salt, nil, info)
	pt := tpm2.ECPoint{
		XRaw: make([]byte, 32),
		YRaw: make([]byte, 32),
	}
	if _, err := io.ReadFull(r, pt.XRaw); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, pt.YRaw); err != nil {
		panic(err)
	}
	return pt
}

// deterministicSigningKeyTmpl creates an ECC P-256 primary signing key template.
func deterministicSigningKeyTmpl(salt, applicationParam []byte) tpm2.Public {
	info := append([]byte("tpm-fido-signing-key"), applicationParam...)
	return tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point:   deriveECPoint(salt, info),
		},
	}
}

// encodeECDSASig formats (r, s) as a canonical ASN.1 DER ECDSA signature with Low-S normalization.
func encodeECDSASig(r, sIn *big.Int) ([]byte, error) {
	s := new(big.Int).Set(sIn)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	return b.Bytes()
}

var baseTime = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

func (t *TPM) Counter() uint32 {
	unix := time.Now().Unix()
	return uint32(unix - baseTime.Unix())
}

// RegisterKey creates a new deterministic Primary Signing Key in the TPM for the given applicationParam.
// Returns the 32-byte salt as the keyHandle.
func (t *TPM) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	salt := mustRand(saltSizeBytes)
	tmpl := deterministicSigningKeyTmpl(salt, applicationParam)

	handle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreatePrimary signing key err: %w", err)
	}
	defer tpm2.FlushContext(tpm, handle)

	pub, _, _, err := tpm2.ReadPublic(tpm, handle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read public key err: %w", err)
	}

	x := new(big.Int).SetBytes(pub.ECCParameters.Point.XRaw)
	y := new(big.Int).SetBytes(pub.ECCParameters.Point.YRaw)

	return salt, x, y, nil
}

// DeriveCredRandom derives a credential-specific random value for the hmac-secret extension.
func (t *TPM) DeriveCredRandom(keyHandle []byte) ([]byte, error) {
	var seed []byte

	if len(keyHandle) == saltSizeBytes {
		seed = keyHandle
	} else {
		// Legacy keyHandle format (> 32 bytes)
		dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))
		if _, err := dec.Decode(); err != nil {
			return nil, fmt.Errorf("invalid key handle: missing private")
		}
		if _, err := dec.Decode(); err != nil {
			return nil, fmt.Errorf("invalid key handle: missing public")
		}
		var err error
		if seed, err = dec.Decode(); err != nil {
			return nil, fmt.Errorf("invalid key handle: missing seed")
		}
	}

	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("credential-random"))
	return mac.Sum(nil), nil
}

// ValidateKeyHandle checks if the credential ID is a valid key handle.
func (t *TPM) ValidateKeyHandle(keyHandle []byte) error {
	if len(keyHandle) == saltSizeBytes {
		return nil
	}

	// Legacy keyHandle format (> 32 bytes)
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))
	for i := 0; i < 3; i++ {
		if _, err := dec.Decode(); err != nil {
			return fmt.Errorf("failed decode legacy field %d: %w", i, err)
		}
	}
	if _, err := dec.Decode(); err != io.EOF {
		return fmt.Errorf("trailing data mismatch: %w", err)
	}
	return nil
}

// SignASN1 signs the digest using the TPM key corresponding to keyHandle.
func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	var keyHandleTPM tpmutil.Handle

	if len(keyHandle) == saltSizeBytes {
		tmpl := deterministicSigningKeyTmpl(keyHandle, applicationParam)
		handle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tmpl)
		if err != nil {
			return nil, fmt.Errorf("CreatePrimary signing key err: %w", err)
		}
		keyHandleTPM = handle
	} else {
		// Legacy keyHandle format
		handle, err := loadLegacyKey(tpm, keyHandle, applicationParam)
		if err != nil {
			return nil, err
		}
		keyHandleTPM = handle
	}
	defer tpm2.FlushContext(tpm, keyHandleTPM)

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}

	sig, err := tpm2.Sign(tpm, keyHandleTPM, "", digest[:], nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("sign err: %w", err)
	}

	return encodeECDSASig(sig.ECC.R, sig.ECC.S)
}

func loadLegacyKey(tpm io.ReadWriteCloser, keyHandle, applicationParam []byte) (tpmutil.Handle, error) {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))
	private, err := dec.Decode()
	if err != nil {
		return 0, fmt.Errorf("invalid key handle (private): %w", err)
	}
	public, err := dec.Decode()
	if err != nil {
		return 0, fmt.Errorf("invalid key handle (public): %w", err)
	}
	seed, err := dec.Decode()
	if err != nil {
		return 0, fmt.Errorf("invalid key handle (seed): %w", err)
	}

	info := append([]byte("tpm-fido-application-key"), applicationParam...)
	srkTemplate := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagRestricted | tpm2.FlagDecrypt |
			tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
			Point:   deriveECPoint(seed, info),
		},
	}

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return 0, fmt.Errorf("CreatePrimary key err: %w", err)
	}
	defer tpm2.FlushContext(tpm, parentHandle)

	key, _, err := tpm2.Load(tpm, parentHandle, "", public, private)
	if err != nil {
		return 0, fmt.Errorf("Load err: %w", err)
	}
	return key, nil
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
