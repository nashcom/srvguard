// srvguard — Nash!Com Service Guard
// Universal service launcher and secret manager for Vault-integrated workloads.
// Fetches secrets from HashiCorp Vault, writes them to the configured output
// backend (files or kernel keyring), launches and supervises a child process,
// and signals it when secrets are rotated.

package main

import (
  "crypto/tls"
  "crypto/x509"
  "encoding/json"
  "fmt"
  "io"
  "log"
  "net/http"
  "os"
  "os/exec"
  "os/signal"
  "strings"
  "syscall"
  "time"
)

const (
  Version   = "0.9.0"
  AppName   = "Nash!Com Service Guard"
  Copyright = "Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved."
)

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

// OutputMode controls how fetched secrets are delivered to consumers.
type OutputMode string

const (
  OutputFiles   OutputMode = "files"   // write cert/key/password to disk or tmpfs
  OutputKeyring OutputMode = "keyring" // store in Linux kernel keyring
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
  // Vault connection
  VaultAddr      string
  RoleIDFile     string // path to file containing role_id
  SecretIDFile   string // path to file containing secret_id
  CACertFile     string // path to CA cert for TLS verification
  SecretPath     string // KV v2 path e.g. secret/data/certs/myserver/tls

  // Secret path
  SecretMount   string // KV v2 mount  e.g. secret
  SecretFQDN    string // server FQDN  e.g. myserver.example.com
  SecretType    string // tls, rsa, ecdsa

  // Output
  Mode           OutputMode
  OutputDir      string // for files mode: directory to write cert/key/password
  KeyringLabel   string // for keyring mode: label for the kernel key

  // Template processing
  TemplateSrc  string // path to config template (e.g. nginx.conf.template)
  TemplateDst  string // path to write processed config (e.g. /etc/nginx/nginx.conf)

  // Authentication method
  AuthMethod     string // "file" (default), "cert" (mTLS), "systemd" or "k8s"
  ClientEncFile  string // path to machine-encrypted client cert bundle (cert auth)
  WrapTokenFile  string // path to one-time Vault wrap token (cert auth bootstrap)
  SystemdCred    string // systemd credential name holding the Vault token (systemd auth)
  K8sTokenFile   string // path to Kubernetes service account JWT (k8s auth)
  K8sRole        string // Vault role name for Kubernetes auth
  K8sAuthMount   string // Vault Kubernetes auth mount path (default: kubernetes)

  // Process supervision
  Command          []string       // child process command + args
  ReloadSignal     syscall.Signal // signal to send on secret rotation (default SIGHUP)
  ReloadContainer  string         // docker container name to signal on rotation (sidecar mode)
  PollInterval     time.Duration  // how often to check for secret changes
}

// loadConfig reads configuration from environment variables.
// All variables are prefixed SRVGUARD_.
func loadConfig() (*Config, error) {
  cfg := &Config{
    VaultAddr:       envOrDefault("SRVGUARD_ADDR",             "https://127.0.0.1:8200"),
    AuthMethod:      envOrDefault("SRVGUARD_AUTH_METHOD",      "file"),
    ClientEncFile:   envOrDefault("SRVGUARD_CLIENT_ENC_FILE",  "/etc/srvguard/client.enc"),
    WrapTokenFile:   envOrDefault("SRVGUARD_WRAP_TOKEN_FILE",  "/etc/srvguard/wrap-token"),
    SystemdCred:     envOrDefault("SRVGUARD_SYSTEMD_CRED",     "vault-token"),
    K8sTokenFile:    envOrDefault("SRVGUARD_K8S_TOKEN_FILE",   "/var/run/secrets/kubernetes.io/serviceaccount/token"),
    K8sRole:         os.Getenv("SRVGUARD_K8S_ROLE"),
    K8sAuthMount:    envOrDefault("SRVGUARD_K8S_AUTH_MOUNT",   "kubernetes"),
    RoleIDFile:      envOrDefault("SRVGUARD_ROLE_ID_FILE",     "/etc/srvguard/role_id"),
    SecretIDFile:    envOrDefault("SRVGUARD_SECRET_ID_FILE",   "/etc/srvguard/secret_id"),
    CACertFile:      envOrDefault("SRVGUARD_CACERT",           "/etc/srvguard/cacert.pem"),
    SecretMount:     envOrDefault("SRVGUARD_SECRET_MOUNT",     "secret"),
    SecretFQDN:      os.Getenv("SRVGUARD_SECRET_FQDN"),
    SecretType:      envOrDefault("SRVGUARD_SECRET_TYPE",      "tls"),
    SecretPath:      os.Getenv("SRVGUARD_SECRET_PATH"),
    Mode:            OutputMode(envOrDefault("SRVGUARD_OUTPUT_MODE", string(OutputFiles))),
    OutputDir:       envOrDefault("SRVGUARD_OUTPUT_DIR",       "/run/srvguard/certs"),
    KeyringLabel:    envOrDefault("SRVGUARD_KEYRING_LABEL",    "srvguard"),
    TemplateSrc:     os.Getenv("SRVGUARD_TEMPLATE_SRC"),
    TemplateDst:     os.Getenv("SRVGUARD_TEMPLATE_DST"),
    PollInterval:    envDuration("SRVGUARD_POLL_INTERVAL",     60*time.Second),
    ReloadSignal:    envSignal("SRVGUARD_RELOAD_SIGNAL",       syscall.SIGHUP),
    ReloadContainer: os.Getenv("SRVGUARD_RELOAD_CONTAINER"),
  }

  // resolve secret path — explicit override takes priority
  if cfg.SecretPath == "" {
    if cfg.SecretFQDN == "" {
      return nil, fmt.Errorf("set SRVGUARD_SECRET_FQDN (e.g. myserver.example.com) or SRVGUARD_SECRET_PATH for a full path override")
    }
    cfg.SecretPath = fmt.Sprintf("%s/data/certs/%s/%s",
      cfg.SecretMount, cfg.SecretFQDN, cfg.SecretType)
  }

  // child command comes from remaining args after --
  cfg.Command = childCommand()

  return cfg, nil
}

// -----------------------------------------------------------------------------
// Vault client
// -----------------------------------------------------------------------------

// vaultClient wraps an HTTP client configured for a specific Vault instance.
type vaultClient struct {
  addr   string
  http   *http.Client
  token  string
}

// newVaultClient creates an HTTP client with the configured CA certificate.
// When AuthMethod is "cert" the client certificate bundle is loaded (or
// bootstrapped via the wrap token) and attached for mTLS.
func newVaultClient(cfg *Config) (*vaultClient, error) {
  pool := x509.NewCertPool()

  if cfg.CACertFile != "" {
    pem, err := os.ReadFile(cfg.CACertFile)
    if err != nil {
      return nil, fmt.Errorf("reading CA cert: %w", err)
    }
    if !pool.AppendCertsFromPEM(pem) {
      return nil, fmt.Errorf("no valid certificates found in %s", cfg.CACertFile)
    }
  }

  tlsCfg := &tls.Config{RootCAs: pool}

  if cfg.AuthMethod == "cert" {
    clientCert, err := loadClientCert(cfg, pool)
    if err != nil {
      return nil, fmt.Errorf("loading mTLS client cert: %w", err)
    }
    tlsCfg.Certificates = []tls.Certificate{clientCert}
  }

  transport := &http.Transport{
    TLSClientConfig: tlsCfg,
  }

  return &vaultClient{
    addr: strings.TrimRight(cfg.VaultAddr, "/"),
    http: &http.Client{
      Transport: transport,
      Timeout:   15 * time.Second,
    },
  }, nil
}

// login dispatches to the appropriate authentication method.
func (c *vaultClient) login(cfg *Config) error {
  switch cfg.AuthMethod {
  case "cert":
    return c.loginCert()
  case "systemd":
    return c.loginSystemd(cfg)
  case "k8s":
    return c.loginK8s(cfg)
  default: // "file", "approle" (alias), or unset
    return c.loginAppRole(cfg)
  }
}

// loginCert authenticates using the mTLS client certificate already loaded
// in the HTTP transport.  The cert auth role is always "srvguard".
func (c *vaultClient) loginCert() error {
  body, _ := json.Marshal(map[string]string{"name": "srvguard"})

  resp, err := c.post("/v1/auth/cert/login", "", body)
  if err != nil {
    return fmt.Errorf("cert login: %w", err)
  }
  defer resp.Body.Close()

  var result struct {
    Auth struct {
      ClientToken string `json:"client_token"`
    } `json:"auth"`
  }

  if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
    return fmt.Errorf("decoding cert login response: %w", err)
  }

  if result.Auth.ClientToken == "" {
    return fmt.Errorf("vault cert login returned empty token")
  }

  c.token = result.Auth.ClientToken
  return nil
}

// loginAppRole performs an AppRole login and stores the resulting token.
func (c *vaultClient) loginAppRole(cfg *Config) error {
  roleID, err := readFile(cfg.RoleIDFile)
  if err != nil {
    return fmt.Errorf("reading role_id: %w", err)
  }

  secretID, err := readFile(cfg.SecretIDFile)
  if err != nil {
    return fmt.Errorf("reading secret_id: %w", err)
  }

  body, _ := json.Marshal(map[string]string{
    "role_id":   roleID,
    "secret_id": secretID,
  })

  resp, err := c.post("/v1/auth/approle/login", "", body)
  if err != nil {
    return fmt.Errorf("approle login: %w", err)
  }
  defer resp.Body.Close()

  var result struct {
    Auth struct {
      ClientToken string `json:"client_token"`
    } `json:"auth"`
  }

  if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
    return fmt.Errorf("decoding login response: %w", err)
  }

  if result.Auth.ClientToken == "" {
    return fmt.Errorf("vault login returned empty token")
  }

  c.token = result.Auth.ClientToken
  return nil
}

// secretVersion returns the current version number of a KV v2 secret.
// This is a cheap metadata-only call — no secret data is returned.
func (c *vaultClient) secretVersion(path string) (int, error) {
  metaPath := kvMetaPath(path)

  resp, err := c.get(metaPath)
  if err != nil {
    return 0, err
  }
  defer resp.Body.Close()

  var result struct {
    Data struct {
      CurrentVersion int `json:"current_version"`
    } `json:"data"`
  }

  if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
    return 0, fmt.Errorf("decoding metadata: %w", err)
  }

  return result.Data.CurrentVersion, nil
}

// fetchSecret retrieves the latest version of a KV v2 secret.
// Returns the data map (field name → value).
func (c *vaultClient) fetchSecret(path string) (map[string]string, error) {
  resp, err := c.get(path)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()

  var result struct {
    Data struct {
      Data map[string]string `json:"data"`
    } `json:"data"`
  }

  if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
    return nil, fmt.Errorf("decoding secret: %w", err)
  }

  return result.Data.Data, nil
}

// -----------------------------------------------------------------------------
// Output backends
// -----------------------------------------------------------------------------

// writeToFiles writes cert/key/password fields to the configured output directory.
func writeToFiles(data map[string]string, dir string) error {
  if err := os.MkdirAll(dir, 0700); err != nil {
    return fmt.Errorf("creating output dir: %w", err)
  }

  files := map[string]string{
    "server.crt":    data["chain"],
    "server.key":    data["encrypted_key"],
    "ssl.password":  data["key_password"],
  }

  for name, content := range files {
    if content == "" {
      continue
    }
    path := dir + "/" + name
    if err := os.WriteFile(path, []byte(content), 0600); err != nil {
      return fmt.Errorf("writing %s: %w", name, err)
    }
  }

  log.Printf("secrets written to %s", dir)
  return nil
}

// writeToKeyring stores a single secret value in the Linux kernel keyring.
// Implemented in keyring.go — stub here for other platforms.
func writeToKeyring(label string, data map[string]string) error {
  return keyringWrite(label, data)
}

// -----------------------------------------------------------------------------
// Process supervision
// -----------------------------------------------------------------------------

// supervisor manages a single child process.
type supervisor struct {
  cfg  *Config
  cmd  *exec.Cmd
  done chan struct{}
}

// start launches the child process and returns immediately.
func (s *supervisor) start() error {
  if len(s.cfg.Command) == 0 {
    return nil // no child process configured, secret-only mode
  }

  s.cmd = exec.Command(s.cfg.Command[0], s.cfg.Command[1:]...)
  s.cmd.Stdout = os.Stdout
  s.cmd.Stderr = os.Stderr
  s.cmd.SysProcAttr = newSysProcAttr()

  if err := s.cmd.Start(); err != nil {
    return fmt.Errorf("starting %s: %w", s.cfg.Command[0], err)
  }

  log.Printf("started %s (pid %d)", s.cfg.Command[0], s.cmd.Process.Pid)

  go func() {
    s.cmd.Wait()
    close(s.done)
  }()

  return nil
}

// reload sends the configured signal to the managed process or container.
func (s *supervisor) reload() {
  // sidecar mode — signal a sibling Docker container by name
  if s.cfg.ReloadContainer != "" {
    log.Printf("sending %s to container %s", s.cfg.ReloadSignal, s.cfg.ReloadContainer)
    out, err := exec.Command("docker", "kill",
      "--signal", s.cfg.ReloadSignal.String(),
      s.cfg.ReloadContainer).CombinedOutput()
    if err != nil {
      log.Printf("docker signal failed: %v — %s", err, out)
    }
    return
  }

  // child process mode — signal directly
  if s.cmd == nil || s.cmd.Process == nil {
    return
  }
  log.Printf("sending %s to %s (pid %d)",
    s.cfg.ReloadSignal, s.cfg.Command[0], s.cmd.Process.Pid)
  s.cmd.Process.Signal(s.cfg.ReloadSignal)
}

// stop sends SIGTERM to the child process.
func (s *supervisor) stop() {
  if s.cmd == nil || s.cmd.Process == nil {
    return
  }
  s.cmd.Process.Signal(syscall.SIGTERM)
}

// -----------------------------------------------------------------------------
// Version / Help / Config dump
// -----------------------------------------------------------------------------

// varDef defines a single environment variable with its default and description.
type varDef struct {
  name string
  def  string
  desc string
}

// varDefs is the single source of truth for all SRVGUARD_ variables.
var varDefs = []varDef{
  {"SRVGUARD_ADDR",             "https://127.0.0.1:8200",   "Vault server URL  e.g. https://vault.example.com:8200"},
  {"SRVGUARD_AUTH_METHOD",      "file",                     "Auth method: file (default), cert (mTLS), systemd, k8s"},
  {"SRVGUARD_CLIENT_ENC_FILE",  "/etc/srvguard/client.enc", "Machine-encrypted mTLS client cert bundle (cert auth)"},
  {"SRVGUARD_WRAP_TOKEN_FILE",  "/etc/srvguard/wrap-token", "One-time Vault wrap token for first-time cert bootstrap"},
  {"SRVGUARD_SYSTEMD_CRED",     "vault-token",              "systemd credential name holding Vault token (systemd auth)"},
  {"SRVGUARD_K8S_TOKEN_FILE",   "/var/run/secrets/kubernetes.io/serviceaccount/token", "K8s service account JWT path (k8s auth)"},
  {"SRVGUARD_K8S_ROLE",         "",                         "Vault role name for Kubernetes auth (required for k8s auth)"},
  {"SRVGUARD_K8S_AUTH_MOUNT",   "kubernetes",               "Vault Kubernetes auth mount path (k8s auth)"},
  {"SRVGUARD_ROLE_ID_FILE",     "/etc/srvguard/role_id",    "AppRole role_id file  e.g. /etc/srvguard/role_id"},
  {"SRVGUARD_SECRET_ID_FILE",   "/etc/srvguard/secret_id",  "AppRole secret_id file  e.g. /etc/srvguard/secret_id"},
  {"SRVGUARD_CACERT",           "/etc/srvguard/cacert.pem", "CA cert for Vault TLS  e.g. /etc/srvguard/cacert.pem"},
  {"SRVGUARD_SECRET_MOUNT",     "secret",                   "KV v2 mount point  e.g. secret"},
  {"SRVGUARD_SECRET_FQDN",      "",                         "Server FQDN for secret path  e.g. myserver.example.com  (required unless SECRET_PATH set)"},
  {"SRVGUARD_SECRET_TYPE",      "tls",                      "Secret type: tls, rsa, ecdsa"},
  {"SRVGUARD_SECRET_PATH",      "",                         "Full KV v2 path override  e.g. secret/data/certs/myserver/tls"},
  {"SRVGUARD_OUTPUT_MODE",      "files",                    "Output backend: files or keyring"},
  {"SRVGUARD_OUTPUT_DIR",       "/run/srvguard/certs",      "Output directory (files mode)  e.g. /run/certs"},
  {"SRVGUARD_KEYRING_LABEL",    "srvguard",                 "Kernel keyring label  e.g. myapp-tls"},
  {"SRVGUARD_TEMPLATE_SRC",     "",                         "Config template  e.g. /etc/nginx/nginx.conf.template"},
  {"SRVGUARD_TEMPLATE_DST",     "",                         "Rendered config  e.g. /etc/nginx/nginx.conf"},
  {"SRVGUARD_POLL_INTERVAL",    "60s",                      "Poll interval  e.g. 30s, 5m, 1h"},
  {"SRVGUARD_RELOAD_SIGNAL",    "HUP",                      "Signal on rotation: HUP, TERM, USR1, USR2"},
  {"SRVGUARD_RELOAD_CONTAINER", "",                         "Docker container to signal  e.g. nginx"},
}

// effective returns the env var value or the default if not set.
func (v varDef) effective() string {
  if val := os.Getenv(v.name); val != "" {
    return val
  }
  return v.def
}

func printBanner() {
  fmt.Printf("\n%s %s\n%s\n\n", AppName, Version, Copyright)
}

func printVersion() {
  printBanner()
}

// truncCol truncates a string to n runes, appending "…" if it was longer.
// Keeps the help table columns aligned even when values exceed the column width.
func truncCol(s string, n int) string {
  r := []rune(s)
  if len(r) <= n {
    return s
  }
  return string(r[:n-1]) + "…"
}

// printHelp prints the full help table with default, effective value and description.
func printHelp() {
  printBanner()
  fmt.Printf("Usage: srvguard [--version] [--help] [-- <command> [args...]]\n\n")
  fmt.Printf("%-30s  %-25s  %-25s  %s\n", "Variable", "Default", "Effective", "Description / Example")
  fmt.Printf("%s\n", strings.Repeat("-", 160))
  for _, v := range varDefs {
    fmt.Printf("%-30s  %-25s  %-25s  %s\n",
      v.name,
      truncCol(v.def, 25),
      truncCol(v.effective(), 25),
      v.desc)
  }
  fmt.Println()
}

// dumpConfig prints variable = effective value at startup — no description.
func dumpConfig() {
  log.Printf("%-30s  %s", "Variable", "Effective Value")
  log.Printf("%s", strings.Repeat("-", 80))
  for _, v := range varDefs {
    log.Printf("%-30s  %s", v.name, v.effective())
  }
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

func main() {
  // handle --version and --help before anything else
  for _, arg := range os.Args[1:] {
    switch arg {
    case "--version", "-v":
      printVersion()
      return
    case "--help", "-h":
      printHelp()
      return
    }
  }

  log.SetPrefix("srvguard: ")
  log.SetFlags(log.Ltime)

  fmt.Println()
  log.Printf("%s %s -- %s", AppName, Version, Copyright)
  fmt.Println()

  dumpConfig()

  cfg, err := loadConfig()
  if err != nil {
    fmt.Println()
    log.Fatalf("config: %v", err)
  }
  fmt.Println()

  client, err := newVaultClient(cfg)
  if err != nil {
    log.Fatalf("vault client: %v", err)
  }

  if err := client.login(cfg); err != nil {
    log.Fatalf("vault login: %v", err)
  }
  log.Printf("authenticated to Vault at %s", cfg.VaultAddr)

  // initial secret fetch
  data, err := client.fetchSecret(cfg.SecretPath)
  if err != nil {
    log.Fatalf("initial secret fetch: %v", err)
  }

  if err := writeSecrets(cfg, data); err != nil {
    log.Fatalf("writing secrets: %v", err)
  }

  // process config template before starting the managed service
  if cfg.TemplateSrc != "" && cfg.TemplateDst != "" {
    if err := processTemplate(cfg.TemplateSrc, cfg.TemplateDst); err != nil {
      log.Fatalf("template processing: %v", err)
    }
  }

  // start child process after secrets are in place
  sup := &supervisor{cfg: cfg, done: make(chan struct{})}
  if err := sup.start(); err != nil {
    log.Fatalf("supervisor: %v", err)
  }

  // handle OS signals
  sigCh := make(chan os.Signal, 1)
  signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

  // poll loop
  ticker := time.NewTicker(cfg.PollInterval)
  defer ticker.Stop()

  knownVersion, _ := client.secretVersion(cfg.SecretPath)

  for {
    select {
    case <-ticker.C:
      version, err := client.secretVersion(cfg.SecretPath)
      if err != nil {
        log.Printf("version check failed: %v — re-authenticating", err)
        if err := client.login(cfg); err != nil {
          log.Printf("re-login failed: %v", err)
          continue
        }
        continue
      }

      if version > knownVersion {
        log.Printf("secret version changed (%d → %d), fetching", knownVersion, version)
        data, err := client.fetchSecret(cfg.SecretPath)
        if err != nil {
          log.Printf("fetch failed: %v", err)
          continue
        }
        if err := writeSecrets(cfg, data); err != nil {
          log.Printf("write failed: %v", err)
          continue
        }
        sup.reload()
        knownVersion = version
      }

    case sig := <-sigCh:
      log.Printf("received %s — shutting down", sig)
      sup.stop()
      return

    case <-sup.done:
      log.Printf("child process exited — shutting down")
      return
    }
  }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// processTemplate reads pszSrc, expands all ${VAR} and $VAR placeholders
// using environment variables, and writes the result to pszDst.
// This replaces the need for the envsubst binary in containers.
func processTemplate(src, dst string) error {
  data, err := os.ReadFile(src)
  if err != nil {
    return fmt.Errorf("reading template %s: %w", src, err)
  }

  expanded := os.Expand(string(data), os.Getenv)

  if err := os.WriteFile(dst, []byte(expanded), 0644); err != nil {
    return fmt.Errorf("writing config %s: %w", dst, err)
  }

  log.Printf("template %s → %s", src, dst)
  return nil
}

// writeSecrets dispatches to the configured output backend.
func writeSecrets(cfg *Config, data map[string]string) error {
  switch cfg.Mode {
  case OutputFiles:
    return writeToFiles(data, cfg.OutputDir)
  case OutputKeyring:
    return writeToKeyring(cfg.KeyringLabel, data)
  default:
    return fmt.Errorf("unknown output mode: %s", cfg.Mode)
  }
}

// kvMetaPath converts a KV v2 data path to its metadata equivalent.
// e.g. secret/data/certs/x/tls → secret/metadata/certs/x/tls
func kvMetaPath(path string) string {
  return strings.Replace(path, "/data/", "/metadata/", 1)
}

// childCommand returns everything after -- in os.Args.
func childCommand() []string {
  for i, arg := range os.Args {
    if arg == "--" {
      return os.Args[i+1:]
    }
  }
  return nil
}

// envOrDefault returns the environment variable value or a default.
func envOrDefault(key, def string) string {
  if v := os.Getenv(key); v != "" {
    return v
  }
  return def
}

// envDuration parses a duration from an environment variable.
func envDuration(key string, def time.Duration) time.Duration {
  v := os.Getenv(key)
  if v == "" {
    return def
  }
  d, err := time.ParseDuration(v)
  if err != nil {
    return def
  }
  return d
}


// readFile reads a file and returns its trimmed content.
func readFile(path string) (string, error) {
  b, err := os.ReadFile(path)
  if err != nil {
    return "", err
  }
  return strings.TrimSpace(string(b)), nil
}

// post sends a JSON POST request to Vault.
func (c *vaultClient) post(path, token string, body []byte) (*http.Response, error) {
  req, err := http.NewRequest(http.MethodPost, c.addr+path,
    io.NopCloser(strings.NewReader(string(body))))
  if err != nil {
    return nil, err
  }
  req.Header.Set("Content-Type", "application/json")
  if token != "" {
    req.Header.Set("X-Vault-Token", token)
  }
  return c.http.Do(req)
}

// get sends an authenticated GET request to Vault.
func (c *vaultClient) get(path string) (*http.Response, error) {
  req, err := http.NewRequest(http.MethodGet, c.addr+path, nil)
  if err != nil {
    return nil, err
  }
  req.Header.Set("X-Vault-Token", c.token)
  return c.http.Do(req)
}
