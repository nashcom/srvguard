// mtls.go — mTLS client certificate support (Linux only)
//
// Provides machine-ID-encrypted client certificate persistence for Vault
// cert auth.  The first time srvguard starts with AuthMethod="cert" it reads
// a one-time Vault response-wrapping token from WrapTokenFile, calls
// /v1/sys/wrapping/unwrap to retrieve the client cert and key issued by the
// Vault internal PKI, encrypts the bundle with an AES-256-GCM key derived
// from /etc/machine-id, and writes it to ClientEncFile.  On subsequent starts
// it decrypts and reloads the bundle directly — the wrap token is no longer
// needed.
//
// Key derivation:  HKDF-SHA256 (secret = machine-id, salt = "srvguard-mtls-v1")
// Ciphertext format: [12-byte nonce][GCM ciphertext+tag]

//go:build linux

package main

import (
  "bytes"
  "crypto/aes"
  "crypto/cipher"
  "crypto/hkdf"
  "crypto/rand"
  "crypto/sha256"
  "crypto/tls"
  "crypto/x509"
  "encoding/json"
  "fmt"
  "io"
  "net/http"
  "os"
  "strings"
  "time"
)

// clientCertBundle is the JSON structure stored (encrypted) in ClientEncFile.
type clientCertBundle struct {
  CertPEM string `json:"cert_pem"`
  KeyPEM  string `json:"key_pem"`
}

// machineKey derives a 32-byte AES key from the host's /etc/machine-id.
// The key is deterministic: same machine → same key on every boot.
// Salt "srvguard-mtls-v1" scopes the key to this application and version.
func machineKey() ([32]byte, error) {
  var key [32]byte

  raw, err := os.ReadFile("/etc/machine-id")
  if err != nil {
    return key, fmt.Errorf("reading /etc/machine-id: %w", err)
  }

  machineID := strings.TrimSpace(string(raw))
  if machineID == "" {
    return key, fmt.Errorf("/etc/machine-id is empty")
  }

  salt := []byte("srvguard-mtls-v1")
  derived, err := hkdf.Key(sha256.New, []byte(machineID), salt, "", 32)
  if err != nil {
    return key, fmt.Errorf("deriving machine key: %w", err)
  }
  copy(key[:], derived)
  return key, nil
}

// encryptBundle encrypts bundle with AES-256-GCM using the machine key and
// writes the result to path with permissions 0400.
// Format: [12-byte random nonce][ciphertext+16-byte GCM tag]
func encryptBundle(path string, bundle []byte) error {
  key, err := machineKey()
  if err != nil {
    return err
  }

  block, err := aes.NewCipher(key[:])
  if err != nil {
    return fmt.Errorf("creating AES cipher: %w", err)
  }

  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return fmt.Errorf("creating GCM: %w", err)
  }

  nonce := make([]byte, gcm.NonceSize()) // 12 bytes
  if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
    return fmt.Errorf("generating nonce: %w", err)
  }

  ciphertext := gcm.Seal(nonce, nonce, bundle, nil)

  if err := os.WriteFile(path, ciphertext, 0400); err != nil {
    return fmt.Errorf("writing encrypted bundle to %s: %w", path, err)
  }

  return nil
}

// decryptBundle reads path and decrypts it with the machine-derived AES key.
func decryptBundle(path string) ([]byte, error) {
  key, err := machineKey()
  if err != nil {
    return nil, err
  }

  ciphertext, err := os.ReadFile(path)
  if err != nil {
    return nil, fmt.Errorf("reading %s: %w", path, err)
  }

  block, err := aes.NewCipher(key[:])
  if err != nil {
    return nil, fmt.Errorf("creating AES cipher: %w", err)
  }

  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return nil, fmt.Errorf("creating GCM: %w", err)
  }

  nonceSize := gcm.NonceSize()
  if len(ciphertext) < nonceSize {
    return nil, fmt.Errorf("encrypted bundle in %s is too short", path)
  }

  nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
  plain, err := gcm.Open(nil, nonce, ct, nil)
  if err != nil {
    return nil, fmt.Errorf("decrypting bundle (wrong machine-id?): %w", err)
  }

  return plain, nil
}

// bundleToCert converts a clientCertBundle to a tls.Certificate.
func bundleToCert(bundle clientCertBundle) (tls.Certificate, error) {
  return tls.X509KeyPair([]byte(bundle.CertPEM), []byte(bundle.KeyPEM))
}

// unwrapClientCert calls /v1/sys/wrapping/unwrap with the token read from
// cfg.WrapTokenFile.  It returns the cert+key extracted from the PKI issue
// response wrapped inside the token.
//
// A plain HTTPS client (no mTLS) is used here — the unwrap endpoint is
// available before a client cert exists.  The wrap token is single-use:
// the file is removed after a successful unwrap.
func unwrapClientCert(cfg *Config, pool *x509.CertPool) (clientCertBundle, error) {
  var bundle clientCertBundle

  wrapToken, err := readFile(cfg.WrapTokenFile)
  if err != nil {
    return bundle, fmt.Errorf("reading wrap token from %s: %w", cfg.WrapTokenFile, err)
  }
  if wrapToken == "" {
    return bundle, fmt.Errorf("wrap token file %s is empty", cfg.WrapTokenFile)
  }

  // plain client — no client cert yet, server cert verified via pool
  httpClient := &http.Client{
    Timeout: 15 * time.Second,
    Transport: &http.Transport{
      TLSClientConfig: &tls.Config{RootCAs: pool},
    },
  }

  addr := strings.TrimRight(cfg.VaultAddr, "/")
  req, err := http.NewRequest(http.MethodPost,
    addr+"/v1/sys/wrapping/unwrap",
    bytes.NewReader([]byte("{}")),
  )
  if err != nil {
    return bundle, fmt.Errorf("building unwrap request: %w", err)
  }
  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("X-Vault-Token", wrapToken)

  resp, err := httpClient.Do(req)
  if err != nil {
    return bundle, fmt.Errorf("unwrap request: %w", err)
  }
  defer resp.Body.Close()

  if resp.StatusCode != http.StatusOK {
    body, _ := io.ReadAll(resp.Body)
    return bundle, fmt.Errorf("unwrap returned HTTP %d: %s", resp.StatusCode, body)
  }

  // Vault PKI issue response (unwrapped):
  // { "data": { "certificate": "PEM...", "private_key": "PEM..." } }
  var result struct {
    Data struct {
      Certificate string `json:"certificate"`
      PrivateKey  string `json:"private_key"`
    } `json:"data"`
  }

  if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
    return bundle, fmt.Errorf("decoding unwrap response: %w", err)
  }

  if result.Data.Certificate == "" || result.Data.PrivateKey == "" {
    return bundle, fmt.Errorf("unwrap response missing certificate or private_key")
  }

  bundle.CertPEM = result.Data.Certificate
  bundle.KeyPEM = result.Data.PrivateKey

  // one-time token has been consumed — remove the file so it is not retried
  if removeErr := os.Remove(cfg.WrapTokenFile); removeErr != nil {
    // non-fatal: token is single-use anyway
    fmt.Fprintf(os.Stderr, "srvguard: warning: could not remove wrap token file: %v\n", removeErr)
  }

  return bundle, nil
}

// loadClientCert returns a tls.Certificate for mTLS.
//
// If ClientEncFile exists: decrypt it with the machine key and return the cert.
// Otherwise: read WrapTokenFile, unwrap from Vault, encrypt and persist the
// bundle, then return the cert.
func loadClientCert(cfg *Config, pool *x509.CertPool) (tls.Certificate, error) {
  // fast path — encrypted bundle already exists on disk
  if _, err := os.Stat(cfg.ClientEncFile); err == nil {
    plain, err := decryptBundle(cfg.ClientEncFile)
    if err != nil {
      return tls.Certificate{}, fmt.Errorf("loading persisted client cert: %w", err)
    }
    var bundle clientCertBundle
    if err := json.Unmarshal(plain, &bundle); err != nil {
      return tls.Certificate{}, fmt.Errorf("unmarshalling client cert bundle: %w", err)
    }
    return bundleToCert(bundle)
  }

  // first-time bootstrap — unwrap from Vault using the one-time token
  bundle, err := unwrapClientCert(cfg, pool)
  if err != nil {
    return tls.Certificate{}, fmt.Errorf("bootstrapping mTLS client cert: %w", err)
  }

  // validate before persisting
  cert, err := bundleToCert(bundle)
  if err != nil {
    return tls.Certificate{}, fmt.Errorf("client cert/key mismatch from Vault: %w", err)
  }

  // persist encrypted bundle
  raw, err := json.Marshal(bundle)
  if err != nil {
    return tls.Certificate{}, fmt.Errorf("marshalling client cert bundle: %w", err)
  }

  if err := encryptBundle(cfg.ClientEncFile, raw); err != nil {
    return tls.Certificate{}, fmt.Errorf("persisting client cert bundle: %w", err)
  }

  fmt.Fprintf(os.Stderr, "srvguard: mTLS client cert bootstrapped and saved to %s\n", cfg.ClientEncFile)
  return cert, nil
}
