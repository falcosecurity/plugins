// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCredentialConnectionString(t *testing.T) {
	for _, typ := range []string{"", TypeConnectionString} {
		cred, err := NewCredential(Config{Type: typ})
		if err != nil {
			t.Fatalf("unexpected error for type %q: %v", typ, err)
		}
		if cred != nil {
			t.Fatalf("expected a nil credential for type %q", typ)
		}
	}
}

func TestNewCredentialUnsupportedType(t *testing.T) {
	if _, err := NewCredential(Config{Type: "bogus"}); err == nil {
		t.Fatalf("expected an error for an unsupported type")
	}
}

func TestNewCredentialManagedIdentity(t *testing.T) {
	// Unlike environment/workload identity, ManagedIdentityCredential
	// construction needs no ambient configuration: it only talks to the
	// Instance Metadata Service lazily, on GetToken.
	cred, err := NewCredential(Config{Type: TypeManagedIdentity})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialManagedIdentityWithClientID(t *testing.T) {
	cred, err := NewCredential(Config{Type: TypeManagedIdentity, ManagedIdentityClientID: "11111111-1111-1111-1111-111111111111"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialManagedIdentityClientIDFromEnv(t *testing.T) {
	t.Setenv(EnvAzureClientID, "22222222-2222-2222-2222-222222222222")

	cred, err := NewCredential(Config{Type: TypeManagedIdentity})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentFromEnvVars(t *testing.T) {
	t.Setenv(EnvAzureTenantID, "11111111-1111-1111-1111-111111111111")
	t.Setenv(EnvAzureClientID, "22222222-2222-2222-2222-222222222222")
	t.Setenv(EnvAzureClientSecret, "fake-secret")

	cred, err := NewCredential(Config{Type: TypeEnvironment})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentFromConfigClientSecret(t *testing.T) {
	// No env vars set at all: every value must come from Config.
	cred, err := NewCredential(Config{
		Type:         TypeEnvironment,
		TenantID:     "11111111-1111-1111-1111-111111111111",
		ClientID:     "22222222-2222-2222-2222-222222222222",
		ClientSecret: "fake-secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentFromConfigClientCertificate(t *testing.T) {
	certPath := writeSelfSignedCert(t)

	cred, err := NewCredential(Config{
		Type:                  TypeEnvironment,
		TenantID:              "11111111-1111-1111-1111-111111111111",
		ClientID:              "22222222-2222-2222-2222-222222222222",
		ClientCertificatePath: certPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentCertificateSendCertificateChainFromConfig(t *testing.T) {
	certPath := writeSelfSignedCert(t)
	sendChain := true

	cred, err := NewCredential(Config{
		Type:                       TypeEnvironment,
		TenantID:                   "11111111-1111-1111-1111-111111111111",
		ClientID:                   "22222222-2222-2222-2222-222222222222",
		ClientCertificatePath:      certPath,
		ClientSendCertificateChain: &sendChain,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentCertificateSendCertificateChainFromEnv(t *testing.T) {
	certPath := writeSelfSignedCert(t)
	t.Setenv(EnvAzureClientSendCertificateChain, "true")

	cred, err := NewCredential(Config{
		Type:                  TypeEnvironment,
		TenantID:              "11111111-1111-1111-1111-111111111111",
		ClientID:              "22222222-2222-2222-2222-222222222222",
		ClientCertificatePath: certPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentClientSecretTakesPrecedenceOverCertificate(t *testing.T) {
	// client_secret is checked before client_certificate_path; point the
	// certificate at a nonexistent file to prove it's never even read when
	// a secret is also present.
	cred, err := NewCredential(Config{
		Type:                  TypeEnvironment,
		TenantID:              "11111111-1111-1111-1111-111111111111",
		ClientID:              "22222222-2222-2222-2222-222222222222",
		ClientSecret:          "fake-secret",
		ClientCertificatePath: "/nonexistent/path/to/cert.pem",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentCertificateFileNotFound(t *testing.T) {
	_, err := NewCredential(Config{
		Type:                  TypeEnvironment,
		TenantID:              "tenant",
		ClientID:              "client",
		ClientCertificatePath: "/nonexistent/path/to/cert.pem",
	})
	if err == nil {
		t.Fatalf("expected an error when client_certificate_path does not exist")
	}
}

func TestNewCredentialEnvironmentCertificateInvalidContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(path, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := NewCredential(Config{
		Type:                  TypeEnvironment,
		TenantID:              "tenant",
		ClientID:              "client",
		ClientCertificatePath: path,
	})
	if err == nil {
		t.Fatalf("expected an error when client_certificate_path does not contain a parseable certificate")
	}
}

func TestNewCredentialEnvironmentConfigFieldsOverrideEnv(t *testing.T) {
	// Set env vars that would fail (no secret/cert at all) and confirm the
	// Config-provided secret is what's actually used, not just tolerated.
	t.Setenv(EnvAzureTenantID, "should-be-overridden")
	t.Setenv(EnvAzureClientID, "should-be-overridden")

	cred, err := NewCredential(Config{
		Type:         TypeEnvironment,
		TenantID:     "11111111-1111-1111-1111-111111111111",
		ClientID:     "22222222-2222-2222-2222-222222222222",
		ClientSecret: "fake-secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialEnvironmentMissingTenantID(t *testing.T) {
	_, err := NewCredential(Config{Type: TypeEnvironment, ClientID: "client", ClientSecret: "secret"})
	if err == nil {
		t.Fatalf("expected an error when tenant_id is missing from both config and environment")
	}
}

func TestNewCredentialEnvironmentMissingClientID(t *testing.T) {
	_, err := NewCredential(Config{Type: TypeEnvironment, TenantID: "tenant", ClientSecret: "secret"})
	if err == nil {
		t.Fatalf("expected an error when client_id is missing from both config and environment")
	}
}

func TestNewCredentialEnvironmentMissingSecretAndCertificate(t *testing.T) {
	_, err := NewCredential(Config{Type: TypeEnvironment, TenantID: "tenant", ClientID: "client"})
	if err == nil {
		t.Fatalf("expected an error when neither client_secret nor client_certificate_path is set")
	}
}

func TestNewCredentialWorkloadIdentity(t *testing.T) {
	// WorkloadIdentityCredential validates AZURE_CLIENT_ID/AZURE_TENANT_ID/
	// AZURE_FEDERATED_TOKEN_FILE are set eagerly, but only reads the token
	// file lazily on GetToken, so a non-existent path is fine here. There is
	// deliberately no Config field for any of this: workload identity is
	// always environment-sourced.
	t.Setenv(EnvAzureTenantID, "11111111-1111-1111-1111-111111111111")
	t.Setenv(EnvAzureClientID, "22222222-2222-2222-2222-222222222222")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")

	cred, err := NewCredential(Config{Type: TypeWorkloadIdentity})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatalf("expected a non-nil credential")
	}
}

func TestNewCredentialWorkloadIdentityMissingEnv(t *testing.T) {
	if _, err := NewCredential(Config{Type: TypeWorkloadIdentity}); err == nil {
		t.Fatalf("expected an error when the AZURE_* workload identity environment variables are unset")
	}
}

func TestResolve(t *testing.T) {
	t.Setenv("IDENTITY_TEST_RESOLVE", "from-env")

	if got := resolve("from-config", "IDENTITY_TEST_RESOLVE"); got != "from-config" {
		t.Fatalf("got %q, want the config value to win", got)
	}
	if got := resolve("", "IDENTITY_TEST_RESOLVE"); got != "from-env" {
		t.Fatalf("got %q, want the env var value as fallback", got)
	}
}

func TestResolveBool(t *testing.T) {
	trueVal, falseVal := true, false

	if got := resolveBool(&falseVal, "IDENTITY_TEST_RESOLVE_BOOL"); got != false {
		t.Fatalf("got %v, want the config value (false) to win even over an unset env var", got)
	}
	if got := resolveBool(&trueVal, "IDENTITY_TEST_RESOLVE_BOOL"); got != true {
		t.Fatalf("got %v, want the config value (true) to win", got)
	}
	if got := resolveBool(nil, "IDENTITY_TEST_RESOLVE_BOOL"); got != false {
		t.Fatalf("got %v, want false when unset in both config and environment", got)
	}

	t.Setenv("IDENTITY_TEST_RESOLVE_BOOL", "true")
	if got := resolveBool(nil, "IDENTITY_TEST_RESOLVE_BOOL"); got != true {
		t.Fatalf("got %v, want the env var value as fallback", got)
	}
	if got := resolveBool(&falseVal, "IDENTITY_TEST_RESOLVE_BOOL"); got != false {
		t.Fatalf("got %v, want the config value (false) to still win over a truthy env var", got)
	}
}

// writeSelfSignedCert writes a self-signed certificate and its RSA private
// key, PEM-encoded together in one file as NewClientCertificateCredential
// expects, and returns the file's path.
func writeSelfSignedCert(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "identity-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)

	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatalf("failed to write certificate file: %v", err)
	}
	return path
}
