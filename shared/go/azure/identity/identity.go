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

// Package identity builds Azure AD (Microsoft Entra ID) credentials shared
// by Azure-based plugins that need to authenticate against Azure services
// without a connection string / shared access key.
package identity

import (
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Auth type identifiers accepted by NewCredential.
const (
	// TypeConnectionString means no Azure AD credential is used; the caller
	// authenticates with a connection string / shared access key instead.
	TypeConnectionString = "connection_string"
	// TypeEnvironment builds a service principal credential (client secret
	// or client certificate) from Config, falling back to the well-known
	// AZURE_* environment variables for any field left empty in Config.
	TypeEnvironment = "environment"
	// TypeManagedIdentity builds a credential from the Azure Instance Metadata
	// Service. Leave ManagedIdentityClientID (or AZURE_CLIENT_ID) empty for
	// the system-assigned identity, or set it to target a user-assigned one.
	TypeManagedIdentity = "managed_identity"
	// TypeWorkloadIdentity builds a credential from a Kubernetes projected
	// service account token, as configured by the AKS workload identity
	// webhook. Unlike the other types this is always sourced from the
	// environment (AZURE_CLIENT_ID, AZURE_TENANT_ID,
	// AZURE_FEDERATED_TOKEN_FILE); there is no Config equivalent.
	TypeWorkloadIdentity = "workload_identity"
)

// Environment variable names read as fallbacks when the corresponding
// Config field is left empty, matching the conventions azidentity itself
// uses for EnvironmentCredential and DefaultAzureCredential.
const (
	EnvAzureTenantID                   = "AZURE_TENANT_ID"
	EnvAzureClientID                   = "AZURE_CLIENT_ID"
	EnvAzureClientSecret               = "AZURE_CLIENT_SECRET"
	EnvAzureClientCertificatePath      = "AZURE_CLIENT_CERTIFICATE_PATH"
	EnvAzureClientCertificatePassword  = "AZURE_CLIENT_CERTIFICATE_PASSWORD"
	EnvAzureClientSendCertificateChain = "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN"
)

// Config selects which Azure AD credential NewCredential builds. Every
// field below is optional: when left empty, NewCredential falls back to
// the matching AZURE_* environment variable (see the Env* constants),
// exactly like azidentity's own EnvironmentCredential does. This lets
// callers mix values from their own configuration with values already
// present in the process environment.
type Config struct {
	// Type is one of TypeConnectionString, TypeEnvironment,
	// TypeManagedIdentity or TypeWorkloadIdentity.
	Type string

	// TenantID, ClientID, ClientSecret, ClientCertificatePath,
	// ClientCertificatePassword and ClientSendCertificateChain configure
	// TypeEnvironment. TenantID and ClientID are always required (from
	// Config or the environment); exactly one of ClientSecret or
	// ClientCertificatePath must resolve to a non-empty value, selecting a
	// client-secret or client-certificate service principal respectively.
	TenantID              string
	ClientID              string
	ClientSecret          string
	ClientCertificatePath string
	// ClientCertificatePassword is the password protecting
	// ClientCertificatePath's private key, if any. Only used with
	// ClientCertificatePath.
	ClientCertificatePassword string
	// ClientSendCertificateChain controls whether the x5c header (the
	// certificate chain) is sent with each token request, as required for
	// Subject Name/Issuer (SNI) authentication. Only used with
	// ClientCertificatePath. Falls back to
	// AZURE_CLIENT_SEND_CERTIFICATE_CHAIN ("1" or "true") when nil.
	ClientSendCertificateChain *bool

	// ManagedIdentityClientID configures TypeManagedIdentity: empty selects
	// the system-assigned identity, set selects a user-assigned identity.
	// Falls back to AZURE_CLIENT_ID when empty.
	ManagedIdentityClientID string
}

// resolve returns configValue if non-empty, otherwise the value of the
// envVar environment variable.
func resolve(configValue, envVar string) string {
	if configValue != "" {
		return configValue
	}
	return os.Getenv(envVar)
}

// resolveBool returns *configValue if non-nil, otherwise whether the
// envVar environment variable is "1" or "true" (case-insensitive) -
// matching how azidentity's own EnvironmentCredential parses
// AZURE_CLIENT_SEND_CERTIFICATE_CHAIN.
func resolveBool(configValue *bool, envVar string) bool {
	if configValue != nil {
		return *configValue
	}
	v := os.Getenv(envVar)
	return v == "1" || strings.EqualFold(v, "true")
}

// NewCredential returns the azcore.TokenCredential described by cfg,
// resolving any field NewCredential needs but Config leaves empty from the
// process environment (see Config).
//
// It returns (nil, nil) for TypeConnectionString (and the empty string, its
// default), signaling that the caller should authenticate with a connection
// string / shared access key instead of an Azure AD token.
func NewCredential(cfg Config) (azcore.TokenCredential, error) {
	switch cfg.Type {
	case "", TypeConnectionString:
		return nil, nil
	case TypeEnvironment:
		return newEnvironmentCredential(cfg)
	case TypeManagedIdentity:
		opts := &azidentity.ManagedIdentityCredentialOptions{}
		if clientID := resolve(cfg.ManagedIdentityClientID, EnvAzureClientID); clientID != "" {
			opts.ID = azidentity.ClientID(clientID)
		}
		return azidentity.NewManagedIdentityCredential(opts)
	case TypeWorkloadIdentity:
		return azidentity.NewWorkloadIdentityCredential(nil)
	default:
		return nil, fmt.Errorf("identity: unsupported auth type %q", cfg.Type)
	}
}

func newEnvironmentCredential(cfg Config) (azcore.TokenCredential, error) {
	tenantID := resolve(cfg.TenantID, EnvAzureTenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("identity: auth.type=%s requires tenant_id (config) or %s (environment variable)", TypeEnvironment, EnvAzureTenantID)
	}
	clientID := resolve(cfg.ClientID, EnvAzureClientID)
	if clientID == "" {
		return nil, fmt.Errorf("identity: auth.type=%s requires client_id (config) or %s (environment variable)", TypeEnvironment, EnvAzureClientID)
	}

	if clientSecret := resolve(cfg.ClientSecret, EnvAzureClientSecret); clientSecret != "" {
		return azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	}

	if certPath := resolve(cfg.ClientCertificatePath, EnvAzureClientCertificatePath); certPath != "" {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("identity: failed to read client_certificate_path %q: %w", certPath, err)
		}
		var password []byte
		if certPassword := resolve(cfg.ClientCertificatePassword, EnvAzureClientCertificatePassword); certPassword != "" {
			password = []byte(certPassword)
		}
		certs, key, err := azidentity.ParseCertificates(certData, password)
		if err != nil {
			return nil, fmt.Errorf("identity: failed to parse client certificate %q: %w", certPath, err)
		}
		opts := &azidentity.ClientCertificateCredentialOptions{
			SendCertificateChain: resolveBool(cfg.ClientSendCertificateChain, EnvAzureClientSendCertificateChain),
		}
		return azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key, opts)
	}

	return nil, fmt.Errorf("identity: auth.type=%s requires client_secret or client_certificate_path (config) or %s / %s (environment variables)", TypeEnvironment, EnvAzureClientSecret, EnvAzureClientCertificatePath)
}
