// k8s.go — Kubernetes service account JWT auth
//
// When SRVGUARD_AUTH_METHOD=k8s, srvguard reads the Pod's service account JWT
// from the standard Kubernetes mount path and authenticates to Vault using the
// Kubernetes auth method.  The JWT is issued and rotated automatically by the
// kubelet — no operator credential management is required.
//
// Vault validates the JWT by calling the Kubernetes API server.  The Vault
// role (SRVGUARD_K8S_ROLE) maps the service account to a set of Vault policies.
//
// Required Vault-side setup (one time per cluster):
//   vault auth enable kubernetes
//   vault write auth/kubernetes/config \
//     kubernetes_host=https://$KUBERNETES_PORT_443_TCP_ADDR:443
//   vault write auth/kubernetes/role/<role> \
//     bound_service_account_names=<sa> \
//     bound_service_account_namespaces=<ns> \
//     policies=<policy> ttl=1h

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// loginK8s authenticates to Vault using the Pod's service account JWT.
// The JWT is read from cfg.K8sTokenFile (default Kubernetes mount path).
// The Vault role and auth mount path are configurable.
func (c *vaultClient) loginK8s(cfg *Config) error {
	jwt, err := readFile(cfg.K8sTokenFile)
	if err != nil {
		return fmt.Errorf("reading K8s service account JWT from %s: %w", cfg.K8sTokenFile, err)
	}
	if jwt == "" {
		return fmt.Errorf("K8s service account JWT at %s is empty", cfg.K8sTokenFile)
	}

	if cfg.K8sRole == "" {
		return fmt.Errorf("SRVGUARD_K8S_ROLE is required for k8s auth")
	}

	body, _ := json.Marshal(map[string]string{
		"jwt":  jwt,
		"role": cfg.K8sRole,
	})

	loginPath := "/v1/auth/" + cfg.K8sAuthMount + "/login"
	resp, err := c.post(loginPath, "", body)
	if err != nil {
		return fmt.Errorf("k8s login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("k8s login returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decoding k8s login response: %w", err)
	}

	if result.Auth.ClientToken == "" {
		return fmt.Errorf("vault k8s login returned empty token")
	}

	c.token = result.Auth.ClientToken
	return nil
}
