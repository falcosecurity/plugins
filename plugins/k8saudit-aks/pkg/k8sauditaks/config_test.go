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
			name:    "missing event hub name",
			mutate:  func(c *PluginConfig) { c.EventHubName = "" },
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
				c.EventHubNamespaceConnectionString = "conn"
				c.BlobStorageContainerName = "checkpoints"
			},
			wantErr: true,
		},
		{
			name: "connection_string amqp missing blob container name",
			mutate: func(c *PluginConfig) {
				c.EventHubNamespaceConnectionString = "conn"
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
	tests := []struct {
		name    string
		cfg     PluginConfig
		want    string
		wantErr bool
	}{
		{
			name: "explicit namespace wins",
			cfg:  PluginConfig{EventHubNamespace: "explicit.servicebus.windows.net/"},
			want: "explicit.servicebus.windows.net",
		},
		{
			name: "explicit namespace without trailing slash is unchanged",
			cfg:  PluginConfig{EventHubNamespace: "explicit.servicebus.windows.net"},
			want: "explicit.servicebus.windows.net",
		},
		{
			name: "explicit namespace wins even with a connection string also set",
			cfg: PluginConfig{
				EventHubNamespace:                 "explicit.servicebus.windows.net",
				EventHubNamespaceConnectionString: "Endpoint=sb://other.servicebus.windows.net/;SharedAccessKeyName=x;SharedAccessKey=y",
			},
			want: "explicit.servicebus.windows.net",
		},
		{
			name: "parsed from connection string",
			cfg: PluginConfig{
				EventHubNamespaceConnectionString: "Endpoint=sb://my-ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abc123==",
			},
			want: "my-ns.servicebus.windows.net",
		},
		{
			name: "parsed from connection string when Endpoint is not the first part",
			cfg: PluginConfig{
				EventHubNamespaceConnectionString: "SharedAccessKeyName=RootManageSharedAccessKey;Endpoint=sb://my-ns.servicebus.windows.net/;SharedAccessKey=abc123==",
			},
			want: "my-ns.servicebus.windows.net",
		},
		{
			name:    "neither set",
			cfg:     PluginConfig{},
			wantErr: true,
		},
		{
			name:    "connection string missing endpoint",
			cfg:     PluginConfig{EventHubNamespaceConnectionString: "SharedAccessKeyName=x;SharedAccessKey=y"},
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
