// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.
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
	"encoding/json"
	"log"
	"os"
	"regexp"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs/checkpoints"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
	falcoeventhub "github.com/falcosecurity/plugins/shared/go/azure/eventhub"
	"github.com/invopop/jsonschema"
	"golang.org/x/time/rate"
)

const pluginName = "k8saudit-aks"
const regExpAuditID = `"auditID":[ a-z0-9-"]+`

var regExpCAuditID *regexp.Regexp

type Plugin struct {
	k8saudit.Plugin
	Logger *log.Logger
	Config PluginConfig
}

type PluginConfig struct {
	EventHubNamespaceConnectionString string `json:"event_hub_namespace_connection_string" jsonschema:"title=event_hub_namespace_connection_string,description=The connection string of the EventHub Namespace to read from"`
	EventHubName                      string `json:"event_hub_name" jsonschema:"title=event_hub_name,description=The name of the EventHub to read from"`
	BlobStorageConnectionString       string `json:"blob_storage_connection_string" jsonschema:"title=blob_storage_connection_string,description=The connection string of the Blob Storage to use as checkpoint store"`
	BlobStorageContainerName          string `json:"blob_storage_container_name" jsonschema:"title=blob_storage_container_name,description=The name of the Blob Storage container to use as checkpoint store"`
	RateLimitEventsPerSecond          int    `json:"rate_limit_events_per_second" jsonschema:"title=rate_limit_events_per_second,description=The rate limit of events per second to read from EventHub"`
	RateLimitBurst                    int    `json:"rate_limit_burst" jsonschema:"title=rate_limit_burst,description=The rate limit burst of events to read from EventHub"`
	MaxEventSize                      uint64 `json:"maxEventSize"         jsonschema:"title=Maximum event size,description=Maximum size of single audit event (Default: 262144),default=262144"`
}

func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          21,
		Name:        pluginName,
		Description: "Read Kubernetes Audit Events for AKS from EventHub and use blob storage as checkpoint store",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.1.0",
		EventSource: "k8s_audit",
	}
}

func (p *PluginConfig) SetDefault() {
	p.RateLimitBurst = 200
	p.RateLimitEventsPerSecond = 100
}

// Resets sets the configuration to its default values
func (k *PluginConfig) Reset() {
	k.MaxEventSize = uint64(sdk.DefaultEvtSize)
}

func (p *Plugin) Init(cfg string) error {
	p.Config.Reset()
	p.Plugin.Config.Reset()
	p.Config.SetDefault()
	err := json.Unmarshal([]byte(cfg), &p.Config)
	if err != nil {
		return err
	}

	regExpCAuditID, err = regexp.Compile(regExpAuditID)
	if err != nil {
		return err
	}

	p.Logger = log.New(os.Stderr, "["+pluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)

	return nil
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		// all properties are optional by default
		RequiredFromJSONSchemaTags: true,
		// unrecognized properties don't cause a parsing failures
		AllowAdditionalProperties: true,
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{
		{Value: "default", Desc: "Cluster Name"},
	}, nil
}

func (p *Plugin) Open(_ string) (source.Instance, error) {
	ctx, cancel := context.WithCancel(context.Background())
	checkClient, err := container.NewClientFromConnectionString(p.Config.BlobStorageConnectionString, p.Config.BlobStorageContainerName, nil)
	if err != nil {
		p.Logger.Printf("error opening connection to blob storage: %v", err)
		return nil, err
	}
	p.Logger.Printf("opened connection to blob storage")
	checkpointStore, err := checkpoints.NewBlobStore(checkClient, nil)
	if err != nil {
		p.Logger.Printf("error opening blob checkpoint connection: %v", err)
		return nil, err
	}
	p.Logger.Printf("opened blob checkpoint connection")
	consumerClient, err := azeventhubs.NewConsumerClientFromConnectionString(
		p.Config.EventHubNamespaceConnectionString,
		p.Config.EventHubName,
		azeventhubs.DefaultConsumerGroup,
		nil,
	)
	p.Logger.Printf("opened consumer client")
	if err != nil {
		p.Logger.Printf("error creating consumer client: %v", err)
		return nil, err
	}

	processor, err := azeventhubs.NewProcessor(consumerClient, checkpointStore, nil)
	if err != nil {
		p.Logger.Printf("error creating eventhub processor: %v", err)
		return nil, err
	}

	rateLimiter := rate.NewLimiter(rate.Limit(p.Config.RateLimitEventsPerSecond), p.Config.RateLimitBurst)

	falcoEventHubProcessor := falcoeventhub.Processor{
		RateLimiter: rateLimiter,
		Logger:      p.Logger,
	}

	p.Logger.Printf("created eventhub processor")

	eventsC := make(chan falcoeventhub.Record)
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

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case i, ok := <-eventsC:
				if !ok {
					return
				}
				values, err := p.Plugin.ParseAuditEventsPayload([]byte(i.Properties.Log))
				if err != nil {
					p.Logger.Println(err)
					continue
				}
				for _, j := range values {
					if j.Err != nil {
						p.Logger.Println(j.Err)
						continue
					}
					pushEventC <- *j
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Run the processor
	go func() {
		if err := processor.Run(ctx); err != nil {
			p.Logger.Printf("error running processor: %v", err)
		}
	}()

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
	)
}
