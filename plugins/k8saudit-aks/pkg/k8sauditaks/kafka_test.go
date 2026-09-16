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
	"github.com/segmentio/kafka-go/sasl/plain"
)

func TestNewKafkaSASLMechanismConnectionString(t *testing.T) {
	p := &Plugin{Config: baseConfig()}
	p.Config.Protocol = protocolKafka
	p.Config.EventHubNamespaceConnectionString = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abc123=="

	mechanism, err := p.newKafkaSASLMechanism("ns.servicebus.windows.net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mechanism.Name() != "PLAIN" {
		t.Fatalf("got mechanism %q, want PLAIN", mechanism.Name())
	}
	plainMechanism, ok := mechanism.(plain.Mechanism)
	if !ok {
		t.Fatalf("got %T, want plain.Mechanism", mechanism)
	}
	if plainMechanism.Username != "$ConnectionString" {
		t.Fatalf("got username %q, want $ConnectionString", plainMechanism.Username)
	}
	if plainMechanism.Password != p.Config.EventHubNamespaceConnectionString {
		t.Fatalf("got password %q, want the configured connection string", plainMechanism.Password)
	}
}

func TestNewKafkaSASLMechanismManagedIdentity(t *testing.T) {
	// ManagedIdentityCredential construction needs no ambient config, so
	// this exercises the OAUTHBEARER branch end-to-end without touching
	// the network (GetToken is never called here).
	p := &Plugin{Config: baseConfig()}
	p.Config.Protocol = protocolKafka
	p.Config.Auth.Type = identity.TypeManagedIdentity
	p.Config.EventHubNamespace = "ns.servicebus.windows.net"

	mechanism, err := p.newKafkaSASLMechanism("ns.servicebus.windows.net")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mechanism.Name() != "OAUTHBEARER" {
		t.Fatalf("got mechanism %q, want OAUTHBEARER", mechanism.Name())
	}
	if _, ok := mechanism.(oauthBearerMechanism); !ok {
		t.Fatalf("got %T, want oauthBearerMechanism", mechanism)
	}
}

func TestNewKafkaSASLMechanismEnvironmentMissingCredentials(t *testing.T) {
	unsetEnv(t, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH")

	p := &Plugin{Config: baseConfig()}
	p.Config.Protocol = protocolKafka
	p.Config.Auth.Type = identity.TypeEnvironment
	p.Config.EventHubNamespace = "ns.servicebus.windows.net"

	if _, err := p.newKafkaSASLMechanism("ns.servicebus.windows.net"); err == nil {
		t.Fatalf("expected an error building the credential for the OAUTHBEARER mechanism")
	}
}

func TestKafkaOAuthScope(t *testing.T) {
	// The Kafka OAUTHBEARER token's audience must be the namespace's own
	// host, not a fixed Event Hubs resource: Event Hubs' Kafka head
	// validates the token's audience against the namespace it was issued
	// for, and rejects a token scoped to a different (even if otherwise
	// valid) Event Hubs resource with a SASL authentication failure.
	got := kafkaOAuthScope("my-namespace.servicebus.windows.net")
	want := "https://my-namespace.servicebus.windows.net/.default"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
