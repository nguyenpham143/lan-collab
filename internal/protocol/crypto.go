package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// Crypto errors.
var (
	ErrBadKeySize         = errors.New("protocol: session key must be 32 bytes (AES-256)")
	ErrCiphertextTooShort = errors.New("protocol: encrypted payload shorter than nonce + tag")
	ErrDecrypt            = errors.New("protocol: payload authentication failed")
)

// NewServerTLSConfig makes an in-memory self-signed ECDSA P-256 cert; SSLKEYLOGFILE enables Wireshark decryption.
func NewServerTLSConfig() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("protocol: generate TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("protocol: generate certificate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "lancollab-server", Organization: []string{"LanCollab"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("protocol: create certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
	applyKeyLog(cfg)
	return cfg, nil
}

// CertificateFingerprint returns the hex SHA-256 of cfg's certificate, for clients to pin with -pin.
func CertificateFingerprint(cfg *tls.Config) string {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cfg.Certificates[0].Certificate[0])
	return hex.EncodeToString(sum[:])
}

// NewClientTLSConfig encrypts but does not verify the self-signed server cert; use the pinned variant to verify it.
func NewClientTLSConfig() *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed in-memory certificate; see NewPinnedClientTLSConfig
		MinVersion:         tls.VersionTLS12,
	}
	applyKeyLog(cfg)
	return cfg
}

// NewPinnedClientTLSConfig fails the handshake unless the cert's SHA-256 equals fingerprintHex (empty disables).
func NewPinnedClientTLSConfig(fingerprintHex string) *tls.Config {
	cfg := NewClientTLSConfig()
	want := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(fingerprintHex)), ":", "")
	if want == "" {
		return cfg
	}
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("tls: server sent no certificate")
		}
		sum := sha256.Sum256(rawCerts[0])
		if hex.EncodeToString(sum[:]) != want {
			return errors.New("tls: server certificate fingerprint does not match -pin")
		}
		return nil
	}
	return cfg
}

func applyKeyLog(cfg *tls.Config) {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return
	}
	// The file stays open for the lifetime of the process, like browsers do.
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		cfg.KeyLogWriter = f
	}
}

// GenerateSessionKey returns a random 32-byte AES-256 key.
func GenerateSessionKey() ([]byte, error) {
	key := make([]byte, SessionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("protocol: generate session key: %w", err)
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != SessionKeySize {
		return nil, ErrBadKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptPayload seals with AES-256-GCM, a fresh nonce per call and header bytes 0..21 as AAD: nonce||ct||tag.
func EncryptPayload(key []byte, aad []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxChunkSize {
		return nil, ErrPayloadTooLarge
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize, NonceSize+len(plaintext)+GCMTagSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("protocol: generate nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// DecryptPayload verifies and opens a payload produced by EncryptPayload.
func DecryptPayload(key []byte, aad []byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) < CryptoOverhead {
		return nil, ErrCiphertextTooShort
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, encrypted[:NonceSize], encrypted[NonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
