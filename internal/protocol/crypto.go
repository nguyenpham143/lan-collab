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

// Crypto errors
var (
	ErrBadKeySize         = errors.New("protocol: session key must be 32 bytes (AES-256)")
	ErrCiphertextTooShort = errors.New("protocol: encrypted payload shorter than nonce + tag")
	ErrDecrypt            = errors.New("protocol: payload authentication failed")
)

// NewServerTLSConfig generates a self-signed TLS certificate for the server and returns a tls.Config
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

// CertificateFingerprint returns the SHA-256 fingerprint of the first certificate in the tls.Config
func CertificateFingerprint(cfg *tls.Config) string {
	if cfg == nil || len(cfg.Certificates) == 0 || len(cfg.Certificates[0].Certificate) == 0 {
		return ""
	}
	hash := sha256.Sum256(cfg.Certificates[0].Certificate[0])
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

// NewClientTLSConfig returns a tls.Config that trusts the given fingerprint (SHA-256 hex string)
func NewClientTLSConfig() *tls.Config {
	cfg := &tls.Config{
		InsecureSkipVerify: true, // We'll verify the fingerprint manually
		MinVersion:         tls.VersionTLS12,
	}
	applyKeyLog(cfg)
	return cfg
}

// NewPinnedClientTLSConfig returns a tls.Config that verifies the server's certificate against the given fingerprint (SHA-256 hex string)
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

// applyKeyLog enables TLS key logging if the environment variable SSLKEYLOGFILE is set
func applyKeyLog(cfg *tls.Config) {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
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

// EncryptPayload encrypts the plaintext using AES-256-GCM with a random nonce.
func EncryptPayload(key []byte, header22 []byte, plaintext []byte) ([]byte, error) {
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
	return aead.Seal(nonce, nonce, plaintext, header22), nil
}

// DecryptPayload verifies and opens a payload produced by EncryptPayload.
func DecryptPayload(key []byte, header22 []byte, encrypted []byte) ([]byte, error) {
	if len(encrypted) < CryptoOverhead {
		return nil, ErrCiphertextTooShort
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, encrypted[:NonceSize], encrypted[NonceSize:], header22)
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
