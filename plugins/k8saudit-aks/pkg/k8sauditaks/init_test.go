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

package k8sauditaks

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

// writeSelfSignedCert writes a self-signed certificate and its RSA private
// key, PEM-encoded together in one file as auth.client_certificate_path
// expects, and returns the file's path.
func writeSelfSignedCert(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "k8saudit-aks-test"},
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

// unsetEnv unsets the given environment variables for the duration of the
// test, regardless of what the ambient environment (e.g. a developer's
// machine logged into `az`) happens to have set, and restores them after.
func unsetEnv(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		prev, ok := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("failed to unset %s: %v", name, err)
		}
		if ok {
			t.Cleanup(func() { os.Setenv(name, prev) })
		}
	}
}

func TestInitEnvironmentAuthFromConfig(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {
			"type": "environment",
			"tenant_id": "11111111-1111-1111-1111-111111111111",
			"client_id": "22222222-2222-2222-2222-222222222222",
			"client_secret": "fake-secret"
		},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitEnvironmentAuthFromEnvVar(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
	t.Setenv("AZURE_CLIENT_SECRET", "fake-secret")

	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {"type": "environment"},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitEnvironmentAuthMissingEverything(t *testing.T) {
	unsetEnv(t, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH")

	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {"type": "environment"},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err == nil {
		t.Fatalf("expected an error when no tenant/client/secret is available from config or environment")
	}
}

func TestInitManagedIdentitySystemAssigned(t *testing.T) {
	unsetEnv(t, "AZURE_CLIENT_ID")

	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {"type": "managed_identity"},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitWorkloadIdentityMissingEnv(t *testing.T) {
	unsetEnv(t, "AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE")

	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {"type": "workload_identity"},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err == nil {
		t.Fatalf("expected an error when the workload identity environment variables are unset")
	}
}

func TestInitDefaultConnectionString(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"event_hub_namespace_connection_string": "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y",
		"event_hub_name": "my-hub",
		"blob_storage_connection_string": "conn",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitAMQPEnvironmentAuthClientSecret(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"protocol": "amqp",
		"auth": {
			"type": "environment",
			"tenant_id": "11111111-1111-1111-1111-111111111111",
			"client_id": "22222222-2222-2222-2222-222222222222",
			"client_secret": "fake-secret"
		},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub",
		"blob_storage_account_url": "https://myaccount.blob.core.windows.net",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitAMQPEnvironmentAuthClientCertificate(t *testing.T) {
	certPath := writeSelfSignedCert(t)

	p := &Plugin{}
	cfg := `{
		"protocol": "amqp",
		"auth": {
			"type": "environment",
			"tenant_id": "11111111-1111-1111-1111-111111111111",
			"client_id": "22222222-2222-2222-2222-222222222222",
			"client_certificate_path": "` + certPath + `"
		},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub",
		"blob_storage_account_url": "https://myaccount.blob.core.windows.net",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitEnvironmentAuthClientCertificateSendCertificateChain(t *testing.T) {
	certPath := writeSelfSignedCert(t)

	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {
			"type": "environment",
			"tenant_id": "11111111-1111-1111-1111-111111111111",
			"client_id": "22222222-2222-2222-2222-222222222222",
			"client_certificate_path": "` + certPath + `",
			"client_send_certificate_chain": true
		},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitEnvironmentAuthCertificateFileNotFound(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {
			"type": "environment",
			"tenant_id": "11111111-1111-1111-1111-111111111111",
			"client_id": "22222222-2222-2222-2222-222222222222",
			"client_certificate_path": "/nonexistent/path/to/cert.pem"
		},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err == nil {
		t.Fatalf("expected an error when client_certificate_path does not exist")
	}
}

func TestInitAMQPManagedIdentitySystemAssigned(t *testing.T) {
	unsetEnv(t, "AZURE_CLIENT_ID")

	p := &Plugin{}
	cfg := `{
		"protocol": "amqp",
		"auth": {"type": "managed_identity"},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub",
		"blob_storage_account_url": "https://myaccount.blob.core.windows.net",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitAMQPManagedIdentityUserAssigned(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"protocol": "amqp",
		"auth": {
			"type": "managed_identity",
			"managed_identity_client_id": "11111111-1111-1111-1111-111111111111"
		},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub",
		"blob_storage_account_url": "https://myaccount.blob.core.windows.net",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitKafkaManagedIdentityUserAssigned(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {
			"type": "managed_identity",
			"managed_identity_client_id": "11111111-1111-1111-1111-111111111111"
		},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitAMQPWorkloadIdentity(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")

	p := &Plugin{}
	cfg := `{
		"protocol": "amqp",
		"auth": {"type": "workload_identity"},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub",
		"blob_storage_account_url": "https://myaccount.blob.core.windows.net",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitInvalidProtocol(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"protocol": "mqtt",
		"event_hub_namespace_connection_string": "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y",
		"event_hub_name": "my-hub",
		"blob_storage_connection_string": "conn",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err == nil {
		t.Fatalf("expected an error for an invalid protocol")
	}
}

func TestInitInvalidAuthType(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"protocol": "kafka",
		"auth": {"type": "bogus"},
		"event_hub_namespace": "ns.servicebus.windows.net",
		"event_hub_name": "my-hub"
	}`
	if err := p.Init(cfg); err == nil {
		t.Fatalf("expected an error for an invalid auth type")
	}
}

func TestInitMissingEventHubName(t *testing.T) {
	p := &Plugin{}
	cfg := `{
		"event_hub_namespace_connection_string": "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y",
		"blob_storage_connection_string": "conn",
		"blob_storage_container_name": "checkpoints"
	}`
	if err := p.Init(cfg); err == nil {
		t.Fatalf("expected an error when event_hub_name is missing")
	}
}

func TestInitInvalidJSON(t *testing.T) {
	p := &Plugin{}
	if err := p.Init("not json"); err == nil {
		t.Fatalf("expected an error for invalid init_config JSON")
	}
}
