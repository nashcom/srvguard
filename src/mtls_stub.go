// mtls_stub.go — mTLS stub for non-Linux platforms
//
// mTLS client cert auth is not supported outside Linux: /etc/machine-id is
// a Linux-specific stable host identity.  On non-Linux hosts the cert auth
// method cannot be used and the stub returns an explanatory error.

//go:build !linux

package main

import (
  "crypto/tls"
  "crypto/x509"
  "fmt"
)

func loadClientCert(cfg *Config, pool *x509.CertPool) (tls.Certificate, error) {
  return tls.Certificate{}, fmt.Errorf(
    "mTLS cert auth (SRVGUARD_AUTH_METHOD=cert) requires Linux (/etc/machine-id); use AppRole auth on this platform",
  )
}
