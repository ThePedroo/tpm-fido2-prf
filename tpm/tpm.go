package tpm

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/psanford/tpm-fido/internal/lencode"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	seedSizeBytes = 20
)

type TPM struct {
	devicePath string
	mu         sync.Mutex
}

func (t *TPM) open() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(t.devicePath)
}

func New(devicePath string) (*TPM, error) {
	t := &TPM{
		devicePath: devicePath,
	}

	tpm, err := t.open()
	if err != nil {
		return nil, err
	}
	tpm.Close()

	return t, nil
}

func primaryKeyTmpl(seed, applicationParam []byte) tpm2.Public {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	unique := tpm2.ECPoint{
		XRaw: make([]byte, 32),
		YRaw: make([]byte, 32),
	}
	if _, err := io.ReadFull(r, unique.XRaw); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, unique.YRaw); err != nil {
		panic(err)
	}

	return tpm2.Public{
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
			Point:   unique,
		},
	}
}

var baseTime = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

func (t *TPM) Counter() uint32 {
	unix := time.Now().Unix()
	return uint32(unix - baseTime.Unix())
}

// Register a new key with the TPM for the given applicationParam.
// RegisterKey returns the KeyHandle or an error.
func (t *TPM) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	randSeed := mustRand(seedSizeBytes)

	primaryTmpl := primaryKeyTmpl(randSeed, applicationParam)

	childTmpl := tpm2.Public{
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
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", primaryTmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, parentHandle)

	private, public, _, _, _, err := tpm2.CreateKey(tpm, parentHandle, tpm2.PCRSelection{}, "", "", childTmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreateKey (child) err: %w", err)
	}

	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))

	enc.Encode(private)
	enc.Encode(public)
	enc.Encode(randSeed)

	keyHandle, _, err := tpm2.Load(tpm, parentHandle, "", public, private)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load child key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, keyHandle)

	pub, _, _, err := tpm2.ReadPublic(tpm, keyHandle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read public key err: %w", err)
	}

	x := new(big.Int).SetBytes(pub.ECCParameters.Point.XRaw)
	y := new(big.Int).SetBytes(pub.ECCParameters.Point.YRaw)

	return out.Bytes(), x, y, nil
}

// DeriveCredRandom derives a credential-specific random value for hmac-secret extension
// Extracts the seed from the keyHandle and uses HMAC-SHA256(seed, "credential-random")
func (t *TPM) DeriveCredRandom(keyHandle []byte) ([]byte, error) {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	// Skip private key
	_, err := dec.Decode()
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: missing private")
	}

	// Skip public key
	_, err = dec.Decode()
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: missing public")
	}

	// Get seed
	seed, err := dec.Decode()
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: missing seed")
	}

	// Derive credential random using HMAC-SHA256(seed, "credential-random")
	mac := hmac.New(sha256.New, seed)
	mac.Write([]byte("credential-random"))
	return mac.Sum(nil), nil
}

// Verify if the given credential ID is possibly a key handle produced by this TPM implementation.
func (t *TPM) ValidateKeyHandle(keyHandle []byte) error {
	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	if _, err := dec.Decode(); err != nil {
		return fmt.Errorf("failed decode private: %w", err)
	}

	if _, err := dec.Decode(); err != nil {
		return fmt.Errorf("failed decode public: %w", err)
	}

	if _, err := dec.Decode(); err != nil {
		return fmt.Errorf("failed decode seed: %w", err)
	}

	if _, err := dec.Decode(); err != io.EOF {
		return fmt.Errorf("trailing data mismatch: %w", err)
	}

	return nil
}

func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	private, err := dec.Decode()
	if err != nil {
		log.Printf("TPM SignASN1: invalid key handle (failed decode private), len=%d, err=%v", len(keyHandle), err)

		return nil, fmt.Errorf("invalid key handle: failed decode private: %w", err)
	}

	public, err := dec.Decode()
	if err != nil {
		log.Printf("TPM SignASN1: invalid key handle (failed decode public), len=%d, err=%v", len(keyHandle), err)

		return nil, fmt.Errorf("invalid key handle: failed decode public: %w", err)
	}

	seed, err := dec.Decode()
	if err != nil {
		log.Printf("TPM SignASN1: invalid key handle (failed decode seed), len=%d, err=%v", len(keyHandle), err)

		return nil, fmt.Errorf("invalid key handle: failed decode seed: %w", err)
	}

	_, err = dec.Decode()
	if err != io.EOF {
		log.Printf("TPM SignASN1: invalid key handle (trailing data mismatch), len=%d, err=%v", len(keyHandle), err)

		return nil, fmt.Errorf("invalid key handle: trailing data mismatch: %w", err)
	}

	srkTemplate := primaryKeyTmpl(seed, applicationParam)

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, parentHandle)

	key, _, err := tpm2.Load(tpm, parentHandle, "", public, private)
	if err != nil {
		return nil, fmt.Errorf("Load err: %w", err)
	}

	defer tpm2.FlushContext(tpm, key)

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}

	sig, err := tpm2.Sign(tpm, key, "", digest[:], nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("sign err: %w", err)
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(sig.ECC.R)
		b.AddASN1BigInt(sig.ECC.S)
	})

	return b.Bytes()
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
