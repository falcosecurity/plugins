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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	falcoeventhub "github.com/falcosecurity/plugins/shared/go/azure/eventhub"
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

// An entity-scoped connection string names the Event Hub itself, and the
// SDK rejects a separate non-empty eventHub argument in that case, so the
// plugin must let the SDK resolve the name - whether event_hub_name is left
// empty or repeats the EntityPath.
func TestNewConsumerClientEntityScopedConnectionString(t *testing.T) {
	for _, name := range []string{"", "entity-hub"} {
		t.Run("event_hub_name="+name, func(t *testing.T) {
			p := &Plugin{Config: baseConfig()}
			p.Config.EventHubName = name
			p.Config.EventHubNamespaceConnectionString = testEventHubConnectionString + ";EntityPath=entity-hub"

			client, err := p.newConsumerClient(nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client == nil {
				t.Fatalf("expected a non-nil client")
			}
		})
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

// TestRunProcessorReportsError covers a processor that stops on its own:
// when its load balancing fails (e.g. the Blob checkpoint store answers
// AuthenticationFailed), azeventhubs.Processor.Run returns the error and
// the processor can't be run again. runProcessor must hand that error to
// errC instead of only logging it, or the source silently goes quiet.
func TestRunProcessorReportsError(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := errors.New("checkpoint store: AuthenticationFailed")
	errC := make(chan error, 1)
	p.runProcessor(ctx, func(context.Context) error { return runErr }, errC)

	select {
	case err := <-errC:
		if !errors.Is(err, runErr) {
			t.Fatalf("got error %v, want one wrapping %v", err, runErr)
		}
	default:
		t.Fatalf("expected the processor error to be sent to errC")
	}
}

// TestRunProcessorStopsSilentlyOnCancel confirms that closing the plugin,
// which cancels ctx and makes azeventhubs.Processor.Run return nil, isn't
// reported as a failure.
func TestRunProcessorStopsSilentlyOnCancel(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	errC := make(chan error, 1)
	p.runProcessor(ctx, func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}, errC)

	select {
	case err := <-errC:
		t.Fatalf("expected no error on cancel, got %v", err)
	default:
	}
}

// TestRunProcessorErrorEndsPushSource wires runProcessor to runRecordPump
// the way openAMQP does, with eventsC left open since the AMQP producer
// never closes it, and checks that the processor error reaches Falco as
// the push source's terminal PushEvent.
func TestRunProcessorErrorEndsPushSource(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC := make(chan falcoeventhub.Record)
	errC := make(chan error, 1)
	pushEventC := make(chan source.PushEvent)
	wg := p.runRecordPump(ctx, eventsC, errC, pushEventC)

	runErr := errors.New("checkpoint store: AuthenticationFailed")
	go p.runProcessor(ctx, func(context.Context) error { return runErr }, errC)

	select {
	case evt := <-pushEventC:
		if !errors.Is(evt.Err, runErr) {
			t.Fatalf("got PushEvent.Err %v, want one wrapping %v", evt.Err, runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for the processor error on pushEventC")
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runRecordPump did not exit after reporting the processor error")
	}
}
