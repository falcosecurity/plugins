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

// These connection strings are shaped exactly as the respective Azure SDKs
// require (including base64-looking keys), so that failures here point at
// our own wiring rather than at SDK-side format validation.
const (
	testEventHubConnectionString = "Endpoint=sb://ns.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=ZmFrZWtleQ=="
	testBlobConnectionString     = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=ZmFrZWtleQ==;EndpointSuffix=core.windows.net"
)

func TestNewConsumerClientConnectionString(t *testing.T) {
	p := &Plugin{Config: baseConfig()}
	p.Config.EventHubNamespaceConnectionString = testEventHubConnectionString

	client, err := p.newConsumerClient(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatalf("expected a non-nil client")
	}
}

func TestNewConsumerClientTokenCredential(t *testing.T) {
	p := &Plugin{Config: baseConfig()}
	p.Config.Auth.Type = identity.TypeManagedIdentity
	p.Config.EventHubNamespace = "ns.servicebus.windows.net"

	cred, err := p.newCredential()
	if err != nil {
		t.Fatalf("unexpected error building credential: %v", err)
	}

	client, err := p.newConsumerClient(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatalf("expected a non-nil client")
	}
}

func TestNewBlobContainerClientConnectionString(t *testing.T) {
	p := &Plugin{Config: baseConfig()}
	p.Config.BlobStorageConnectionString = testBlobConnectionString
	p.Config.BlobStorageContainerName = "checkpoints"

	client, err := p.newBlobContainerClient(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatalf("expected a non-nil client")
	}
}

func TestNewBlobContainerClientTokenCredential(t *testing.T) {
	p := &Plugin{Config: baseConfig()}
	p.Config.Auth.Type = identity.TypeManagedIdentity
	p.Config.BlobStorageAccountURL = "https://myaccount.blob.core.windows.net"
	p.Config.BlobStorageContainerName = "checkpoints"

	cred, err := p.newCredential()
	if err != nil {
		t.Fatalf("unexpected error building credential: %v", err)
	}

	client, err := p.newBlobContainerClient(cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatalf("expected a non-nil client")
	}
}

func TestNewBlobContainerClientTokenCredentialTrimsTrailingSlash(t *testing.T) {
	p := &Plugin{Config: baseConfig()}
	p.Config.Auth.Type = identity.TypeManagedIdentity
	p.Config.BlobStorageAccountURL = "https://myaccount.blob.core.windows.net/"
	p.Config.BlobStorageContainerName = "checkpoints"

	cred, err := p.newCredential()
	if err != nil {
		t.Fatalf("unexpected error building credential: %v", err)
	}

	if _, err := p.newBlobContainerClient(cred); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
