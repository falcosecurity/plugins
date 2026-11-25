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
	"testing"

	"github.com/falcosecurity/plugins/shared/go/azure/identity"
)

const (
	testNamespaceConnStr = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y"
	testEntityConnStr    = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y;EntityPath=entity-hub"
)

func baseConfig() PluginConfig {
	var c PluginConfig
	c.SetDefault()
	c.EventHubName = "my-hub"
	return c
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *PluginConfig)
		wantErr bool
	}{
		{
			name: "default amqp + connection_string is valid",
			mutate: func(c *PluginConfig) {
				c.EventHubNamespaceConnectionString = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y"
				c.BlobStorageConnectionString = "conn"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: false,
		},
		{
			name: "missing event hub name with namespace-scoped connection string",
			mutate: func(c *PluginConfig) {
				c.EventHubName = ""
				c.EventHubNamespaceConnectionString = testNamespaceConnStr
				c.BlobStorageConnectionString = "conn"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: true,
		},
		{
			name: "amqp entity-scoped connection string without event hub name is valid",
			mutate: func(c *PluginConfig) {
				c.EventHubName = ""
				c.EventHubNamespaceConnectionString = testEntityConnStr
				c.BlobStorageConnectionString = "conn"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: false,
		},
		{
			name: "amqp entity-scoped connection string with matching event hub name is valid",
			mutate: func(c *PluginConfig) {
				c.EventHubName = "entity-hub"
				c.EventHubNamespaceConnectionString = testEntityConnStr
				c.BlobStorageConnectionString = "conn"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: false,
		},
		{
			name: "amqp entity-scoped connection string with conflicting event hub name",
			mutate: func(c *PluginConfig) {
				c.EventHubNamespaceConnectionString = testEntityConnStr
				c.BlobStorageConnectionString = "conn"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: true,
		},
		{
			name: "kafka entity-scoped connection string without event hub name is valid",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.EventHubName = ""
				c.EventHubNamespaceConnectionString = testEntityConnStr
			},
			wantErr: false,
		},
		{
			name: "missing event hub name with managed_identity",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.Auth.Type = identity.TypeManagedIdentity
				c.EventHubNamespace = "ns.servicebus.windows.net"
				c.EventHubName = ""
			},
			wantErr: true,
		},
		{
			name: "malformed connection string",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.EventHubNamespaceConnectionString = "not-a-connection-string"
			},
			wantErr: true,
		},
		{
			name: "kafka connection_string with conflicting explicit namespace",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.EventHubNamespace = "typo.servicebus.windows.net"
				c.EventHubNamespaceConnectionString = testNamespaceConnStr
			},
			wantErr: true,
		},
		{
			name:    "invalid protocol",
			mutate:  func(c *PluginConfig) { c.Protocol = "mqtt" },
			wantErr: true,
		},
		{
			name:    "invalid auth type",
			mutate:  func(c *PluginConfig) { c.Auth.Type = "bogus" },
			wantErr: true,
		},
		{
			name:    "empty consumer_group",
			mutate:  func(c *PluginConfig) { c.ConsumerGroup = "" },
			wantErr: true,
		},
		{
			name: "connection_string amqp missing event hub connection string",
			mutate: func(c *PluginConfig) {
				c.BlobStorageConnectionString = "conn"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: true,
		},
		{
			name: "connection_string amqp missing blob connection string",
			mutate: func(c *PluginConfig) {
				c.EventHubNamespaceConnectionString = testNamespaceConnStr
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: true,
		},
		{
			name: "connection_string amqp missing blob container name",
			mutate: func(c *PluginConfig) {
				c.EventHubNamespaceConnectionString = testNamespaceConnStr
				c.BlobStorageConnectionString = "conn"
			},
			wantErr: true,
		},
		{
			name: "managed_identity amqp requires namespace and blob account url",
			mutate: func(c *PluginConfig) {
				c.Auth.Type = identity.TypeManagedIdentity
			},
			wantErr: true,
		},
		{
			name: "managed_identity amqp valid",
			mutate: func(c *PluginConfig) {
				c.Auth.Type = identity.TypeManagedIdentity
				c.EventHubNamespace = "ns.servicebus.windows.net"
				c.BlobStorageAccountURL = "https://myaccount.blob.core.windows.net"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: false,
		},
		{
			name: "workload_identity kafka valid, no blob storage needed",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.Auth.Type = identity.TypeWorkloadIdentity
				c.EventHubNamespace = "ns.servicebus.windows.net"
			},
			wantErr: false,
		},
		{
			name: "environment kafka missing namespace",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.Auth.Type = identity.TypeEnvironment
			},
			wantErr: true,
		},
		{
			name: "environment kafka valid",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.Auth.Type = identity.TypeEnvironment
				c.EventHubNamespace = "ns.servicebus.windows.net"
			},
			wantErr: false,
		},
		{
			name: "connection_string kafka valid without explicit namespace",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.EventHubNamespaceConnectionString = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y"
			},
			wantErr: false,
		},
		{
			name: "connection_string kafka missing event hub connection string",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
			},
			wantErr: true,
		},
		{
			name: "managed_identity kafka valid",
			mutate: func(c *PluginConfig) {
				c.Protocol = protocolKafka
				c.Auth.Type = identity.TypeManagedIdentity
				c.EventHubNamespace = "ns.servicebus.windows.net"
			},
			wantErr: false,
		},
		{
			name: "environment amqp valid",
			mutate: func(c *PluginConfig) {
				c.Auth.Type = identity.TypeEnvironment
				c.EventHubNamespace = "ns.servicebus.windows.net"
				c.BlobStorageAccountURL = "https://myaccount.blob.core.windows.net"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: false,
		},
		{
			name: "environment amqp missing blob account url",
			mutate: func(c *PluginConfig) {
				c.Auth.Type = identity.TypeEnvironment
				c.EventHubNamespace = "ns.servicebus.windows.net"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: true,
		},
		{
			name: "workload_identity amqp valid",
			mutate: func(c *PluginConfig) {
				c.Auth.Type = identity.TypeWorkloadIdentity
				c.EventHubNamespace = "ns.servicebus.windows.net"
				c.BlobStorageAccountURL = "https://myaccount.blob.core.windows.net"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: false,
		},
		{
			name: "workload_identity amqp missing blob account url",
			mutate: func(c *PluginConfig) {
				c.Auth.Type = identity.TypeWorkloadIdentity
				c.EventHubNamespace = "ns.servicebus.windows.net"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: true,
		},
		{
			name: "managed_identity amqp missing blob container name",
			mutate: func(c *PluginConfig) {
				c.Auth.Type = identity.TypeManagedIdentity
				c.EventHubNamespace = "ns.servicebus.windows.net"
				c.BlobStorageAccountURL = "https://myaccount.blob.core.windows.net"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseConfig()
			tt.mutate(&c)
			err := c.validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestResolveNamespaceHost(t *testing.T) {
	cs := identity.TypeConnectionString
	mi := identity.TypeManagedIdentity
	tests := []struct {
		name    string
		cfg     PluginConfig
		want    string
		wantErr bool
	}{
		{
			name: "explicit namespace used for non connection_string auth",
			cfg:  PluginConfig{Auth: AuthConfig{Type: mi}, EventHubNamespace: "explicit.servicebus.windows.net/"},
			want: "explicit.servicebus.windows.net",
		},
		{
			name: "explicit namespace without trailing slash is unchanged",
			cfg:  PluginConfig{Auth: AuthConfig{Type: mi}, EventHubNamespace: "explicit.servicebus.windows.net"},
			want: "explicit.servicebus.windows.net",
		},
		{
			name:    "explicit namespace with https scheme is rejected",
			cfg:     PluginConfig{Auth: AuthConfig{Type: mi}, EventHubNamespace: "https://explicit.servicebus.windows.net"},
			wantErr: true,
		},
		{
			name:    "explicit namespace with sb scheme is rejected",
			cfg:     PluginConfig{Auth: AuthConfig{Type: mi}, EventHubNamespace: "sb://explicit.servicebus.windows.net/"},
			wantErr: true,
		},
		{
			name:    "non connection_string auth without namespace",
			cfg:     PluginConfig{Auth: AuthConfig{Type: mi}},
			wantErr: true,
		},
		{
			name: "non connection_string auth ignores the connection string",
			cfg: PluginConfig{
				Auth:                              AuthConfig{Type: mi},
				EventHubNamespace:                 "explicit.servicebus.windows.net",
				EventHubNamespaceConnectionString: "Endpoint=sb://other.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y",
			},
			want: "explicit.servicebus.windows.net",
		},
		{
			// A typo in event_hub_namespace must not send the connection
			// string's shared key to a different broker.
			name: "connection_string auth rejects a conflicting explicit namespace",
			cfg: PluginConfig{
				Auth:                              AuthConfig{Type: cs},
				EventHubNamespace:                 "explicit.servicebus.windows.net",
				EventHubNamespaceConnectionString: "Endpoint=sb://other.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y",
			},
			wantErr: true,
		},
		{
			name: "connection_string auth accepts a matching explicit namespace",
			cfg: PluginConfig{
				Auth:                              AuthConfig{Type: cs},
				EventHubNamespace:                 "My-NS.servicebus.windows.net/",
				EventHubNamespaceConnectionString: "Endpoint=sb://my-ns.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y",
			},
			want: "my-ns.servicebus.windows.net",
		},
		{
			name: "parsed from connection string",
			cfg: PluginConfig{
				Auth:                              AuthConfig{Type: cs},
				EventHubNamespaceConnectionString: "Endpoint=sb://my-ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abc123==",
			},
			want: "my-ns.servicebus.windows.net",
		},
		{
			name: "parsed from connection string when Endpoint is not the first part",
			cfg: PluginConfig{
				Auth:                              AuthConfig{Type: cs},
				EventHubNamespaceConnectionString: "SharedAccessKeyName=RootManageSharedAccessKey;Endpoint=sb://my-ns.servicebus.windows.net/;SharedAccessKey=abc123==",
			},
			want: "my-ns.servicebus.windows.net",
		},
		{
			name: "parsed from entity-scoped connection string",
			cfg: PluginConfig{
				Auth:                              AuthConfig{Type: cs},
				EventHubNamespaceConnectionString: testEntityConnStr,
			},
			want: "ns.servicebus.windows.net",
		},
		{
			name:    "connection_string auth with no connection string",
			cfg:     PluginConfig{Auth: AuthConfig{Type: cs}},
			wantErr: true,
		},
		{
			name: "connection string missing endpoint",
			cfg: PluginConfig{
				Auth:                              AuthConfig{Type: cs},
				EventHubNamespaceConnectionString: "SharedAccessKeyName=x;SharedAccessKey=y",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.resolveNamespaceHost()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil (host=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveEventHubName(t *testing.T) {
	cs := identity.TypeConnectionString
	tests := []struct {
		name    string
		cfg     PluginConfig
		want    string
		wantErr bool
	}{
		{
			name: "namespace-scoped connection string uses event_hub_name",
			cfg:  PluginConfig{Auth: AuthConfig{Type: cs}, EventHubNamespaceConnectionString: testNamespaceConnStr, EventHubName: "my-hub"},
			want: "my-hub",
		},
		{
			name:    "namespace-scoped connection string requires event_hub_name",
			cfg:     PluginConfig{Auth: AuthConfig{Type: cs}, EventHubNamespaceConnectionString: testNamespaceConnStr},
			wantErr: true,
		},
		{
			name: "entity-scoped connection string supplies the name",
			cfg:  PluginConfig{Auth: AuthConfig{Type: cs}, EventHubNamespaceConnectionString: testEntityConnStr},
			want: "entity-hub",
		},
		{
			name: "entity-scoped connection string with matching event_hub_name",
			cfg:  PluginConfig{Auth: AuthConfig{Type: cs}, EventHubNamespaceConnectionString: testEntityConnStr, EventHubName: "entity-hub"},
			want: "entity-hub",
		},
		{
			name:    "entity-scoped connection string with conflicting event_hub_name",
			cfg:     PluginConfig{Auth: AuthConfig{Type: cs}, EventHubNamespaceConnectionString: testEntityConnStr, EventHubName: "my-hub"},
			wantErr: true,
		},
		{
			name: "non connection_string auth ignores EntityPath",
			cfg:  PluginConfig{Auth: AuthConfig{Type: identity.TypeManagedIdentity}, EventHubNamespaceConnectionString: testEntityConnStr, EventHubName: "my-hub"},
			want: "my-hub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.resolveEventHubName()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil (name=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
