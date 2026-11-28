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
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs/checkpoints"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	falcoeventhub "github.com/falcosecurity/plugins/shared/go/azure/eventhub"
	"golang.org/x/time/rate"
)

// openAMQP consumes the EventHub over the native AMQP-based Event Hubs SDK,
// using the Blob Storage checkpoint store, either the connection strings
// (auth.type=connection_string) or an Azure AD credential.
func (p *Plugin) openAMQP(cred azcore.TokenCredential) (source.Instance, error) {
	ctx, cancel := context.WithCancel(context.Background())

	checkClient, err := p.newBlobContainerClient(cred)
	if err != nil {
		p.Logger.Printf("error opening connection to blob storage: %v", err)
		cancel()
		return nil, err
	}
	p.Logger.Printf("opened connection to blob storage")
	checkpointStore, err := checkpoints.NewBlobStore(checkClient, nil)
	if err != nil {
		p.Logger.Printf("error opening blob checkpoint connection: %v", err)
		cancel()
		return nil, err
	}
	p.Logger.Printf("opened blob checkpoint connection")

	consumerClient, err := p.newConsumerClient(cred)
	if err != nil {
		p.Logger.Printf("error creating consumer client: %v", err)
		cancel()
		return nil, err
	}
	p.Logger.Printf("opened consumer client")

	processor, err := azeventhubs.NewProcessor(consumerClient, checkpointStore, nil)
	if err != nil {
		p.Logger.Printf("error creating eventhub processor: %v", err)
		cancel()
		return nil, err
	}

	rateLimiter := rate.NewLimiter(rate.Limit(p.Config.RateLimitEventsPerSecond), p.Config.RateLimitBurst)

	falcoEventHubProcessor := falcoeventhub.Processor{
		RateLimiter: rateLimiter,
		Logger:      p.Logger,
	}

	p.Logger.Printf("created eventhub processor")

	eventsC := make(chan falcoeventhub.Record)
	// Buffered: runProcessor sends here at most once, so it never blocks,
	// even after runRecordPump has returned. See runRecordPump's errC doc.
	errC := make(chan error, 1)
	pushEventC := make(chan source.PushEvent)

	go func() {
		for {
			partitionClient := processor.NextPartitionClient(ctx)
			if partitionClient == nil {
				break
			}
			defer func() {
				// Ensure that pc.Close() is called when the goroutine ends,
				// regardless of whether Process returned an error.
				if cerr := partitionClient.Close(ctx); cerr != nil {
					p.Logger.Printf("error closing partition client: %v", cerr)
				}
			}()
			go func(pc *azeventhubs.ProcessorPartitionClient, ec chan<- falcoeventhub.Record) {
				if err := falcoEventHubProcessor.Process(partitionClient, eventsC, ctx); err != nil {
					p.Logger.Printf("error processing partition client: %v", err)
				}
			}(partitionClient, eventsC)
		}
	}()

	wg := p.runRecordPump(ctx, eventsC, errC, pushEventC)

	// Run the processor
	go p.runProcessor(ctx, processor.Run, errC)

	return source.NewPushInstance(
		pushEventC,
		source.WithInstanceClose(func() {
			// Close consumerClient when the context is canceled
			if err := consumerClient.Close(context.Background()); err != nil {
				p.Logger.Printf("error closing consumer client: %v", err)
			}

			// Cancel must be used here instead of as a defer to ensure that the context is canceled only when
			// the plugin receive a signal from Falco
			cancel()

			wg.Wait()
			close(eventsC)
			close(pushEventC)
		}),
		source.WithInstanceEventSize(uint32(p.Config.MaxEventSize)),
	)
}

// runProcessor runs the EventHub processor with run (processor.Run) until
// ctx is canceled, in which case run returns nil. Any other error means
// that the processor stopped on its own, e.g. because the checkpoint store
// rejected a load balancing request: it has then closed all its partition
// clients, NextPartitionClient returns nil from then on and it can't be
// run again, so no more events would ever be received. The error is sent
// to errC, which must be buffered, so that runRecordPump ends the source
// with it instead of letting Falco wait on a source that went quiet.
func (p *Plugin) runProcessor(ctx context.Context, run func(context.Context) error, errC chan<- error) {
	if err := run(ctx); err != nil {
		p.Logger.Printf("error running processor: %v", err)
		errC <- fmt.Errorf("eventhub processor stopped: %w", err)
	}
}

func (p *Plugin) newConsumerClient(cred azcore.TokenCredential) (*azeventhubs.ConsumerClient, error) {
	if cred != nil {
		return azeventhubs.NewConsumerClient(
			p.Config.EventHubNamespace,
			p.Config.EventHubName,
			p.Config.ConsumerGroup,
			cred,
			nil,
		)
	}
	// An entity-scoped connection string (one with an EntityPath) already
	// names the Event Hub, and the SDK then requires the eventHub argument
	// to be empty, so let it resolve the name from the connection string.
	// validate() has already rejected an event_hub_name that conflicts
	// with the EntityPath.
	entityPath, err := p.Config.connectionStringEntityPath()
	if err != nil {
		return nil, err
	}
	eventHub := p.Config.EventHubName
	if entityPath != "" {
		eventHub = ""
	}
	return azeventhubs.NewConsumerClientFromConnectionString(
		p.Config.EventHubNamespaceConnectionString,
		eventHub,
		p.Config.ConsumerGroup,
		nil,
	)
}

func (p *Plugin) newBlobContainerClient(cred azcore.TokenCredential) (*container.Client, error) {
	if cred != nil {
		containerURL := strings.TrimSuffix(p.Config.BlobStorageAccountURL, "/") + "/" + p.Config.BlobStorageContainerName
		return container.NewClient(containerURL, cred, nil)
	}
	return container.NewClientFromConnectionString(p.Config.BlobStorageConnectionString, p.Config.BlobStorageContainerName, nil)
}
