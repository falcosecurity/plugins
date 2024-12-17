package k8sauditaks

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"

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

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	if i := os.Getenv("EVENTHUB_NAMESPACE_CONNECTION_STRING"); i != "" {
		p.EventHubNamespaceConnectionString = i
	}
	if i := os.Getenv("EVENTHUB_NAME"); i != "" {
		p.EventHubName = i
	}
	if i := os.Getenv("BLOB_STORAGE_CONNECTION_STRING"); i != "" {
		p.BlobStorageConnectionString = i
	}
	if i := os.Getenv("BLOB_STORAGE_CONTAINER_NAME"); i != "" {
		p.BlobStorageContainerName = i
	}
	if i := os.Getenv("RATE_LIMIT_EVENTS_PER_SECOND"); i != "" {
		rateLimitEventsPerSecond, err := strconv.Atoi(i)
		if err != nil {
			return
		}
		p.RateLimitEventsPerSecond = rateLimitEventsPerSecond
	} else {
		p.RateLimitEventsPerSecond = 100
	}
	if i := os.Getenv("RATE_LIMIT_BURST"); i != "" {
		rateLimitBurst, err := strconv.Atoi(i)
		if err != nil {
			return
		}
		p.RateLimitBurst = rateLimitBurst
	} else {
		p.RateLimitBurst = 200
	}
}

func (p *Plugin) Init(cfg string) error {
	// read configuration
	p.Plugin.Config.Reset()
	p.Config.Reset()

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

	// Process events and send to pushEventC
	go func() {
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
			// Cancel the context so that the processor stops
			cancel()
			// Close pushEventC to signal no more events
			close(pushEventC)
		}),
	)
}
