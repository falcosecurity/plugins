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
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
	falcoeventhub "github.com/falcosecurity/plugins/shared/go/azure/eventhub"
	"github.com/falcosecurity/plugins/shared/go/azure/identity"
	"github.com/invopop/jsonschema"
	"github.com/valyala/fastjson"
)

const pluginName = "k8saudit-aks"
const regExpAuditID = `"auditID":[ a-z0-9-"]+`

const (
	protocolAMQP  = "amqp"
	protocolKafka = "kafka"
)

var regExpCAuditID *regexp.Regexp

type Plugin struct {
	k8saudit.Plugin
	Logger *log.Logger
	Config PluginConfig
}

// AuthConfig selects how the plugin authenticates against Azure Event Hubs
// (and, for the amqp protocol, the Blob Storage checkpoint store).
//
// Every field below is optional: when left empty, it falls back to the
// matching AZURE_* environment variable (see identity.Env*), so credentials
// can be supplied either in init_config or via the process environment, or
// a mix of both. The one exception is workload_identity, which is always
// sourced from the environment (AZURE_CLIENT_ID, AZURE_TENANT_ID,
// AZURE_FEDERATED_TOKEN_FILE, as injected by the AKS workload identity
// webhook) and has no config fields of its own.
type AuthConfig struct {
	Type string `json:"type" jsonschema:"title=type,description=The auth type: connection_string (default), environment, managed_identity or workload_identity,enum=connection_string,enum=environment,enum=managed_identity,enum=workload_identity"`

	// ManagedIdentityClientID configures type=managed_identity: leave empty
	// for the system-assigned identity, or set it (or AZURE_CLIENT_ID) to
	// target a user-assigned identity.
	ManagedIdentityClientID string `json:"managed_identity_client_id" jsonschema:"title=managed_identity_client_id,description=Client ID of a user-assigned managed identity (or set AZURE_CLIENT_ID). Only used when type=managed_identity; leave empty to use the system-assigned identity"`

	// TenantID, ClientID, ClientSecret, ClientCertificatePath,
	// ClientCertificatePassword and ClientSendCertificateChain configure
	// type=environment. TenantID and ClientID are always required (here or
	// via AZURE_TENANT_ID / AZURE_CLIENT_ID); exactly one of ClientSecret
	// or ClientCertificatePath must be set (here or via
	// AZURE_CLIENT_SECRET / AZURE_CLIENT_CERTIFICATE_PATH) to select a
	// client-secret or client-certificate service principal.
	TenantID                  string `json:"tenant_id" jsonschema:"title=tenant_id,description=Azure AD tenant ID (or set AZURE_TENANT_ID). Used when type=environment"`
	ClientID                  string `json:"client_id" jsonschema:"title=client_id,description=Service principal client ID (or set AZURE_CLIENT_ID). Used when type=environment"`
	ClientSecret              string `json:"client_secret" jsonschema:"title=client_secret,description=Service principal client secret (or set AZURE_CLIENT_SECRET). Used when type=environment"`
	ClientCertificatePath     string `json:"client_certificate_path" jsonschema:"title=client_certificate_path,description=Path to a PEM or PKCS12 client certificate file including the private key (or set AZURE_CLIENT_CERTIFICATE_PATH). Used when type=environment"`
	ClientCertificatePassword string `json:"client_certificate_password" jsonschema:"title=client_certificate_password,description=Password for client_certificate_path, if any (or set AZURE_CLIENT_CERTIFICATE_PASSWORD). Used when type=environment"`
	// ClientSendCertificateChain controls whether the certificate chain is
	// sent with each token request, as required for Subject Name/Issuer
	// (SNI) authentication. Only meaningful with ClientCertificatePath.
	// Leave unset to fall back to AZURE_CLIENT_SEND_CERTIFICATE_CHAIN ("1"
	// or "true"), which itself defaults to false.
	ClientSendCertificateChain *bool `json:"client_send_certificate_chain" jsonschema:"title=client_send_certificate_chain,description=Whether to send the certificate chain for Subject Name/Issuer (SNI) authentication (or set AZURE_CLIENT_SEND_CERTIFICATE_CHAIN). Used with type=environment and client_certificate_path; defaults to false"`
}

type PluginConfig struct {
	// Protocol selects the transport used to read events from Azure Event
	// Hubs: "amqp" (default, the native Event Hubs SDK) or "kafka" (the
	// Kafka-compatible endpoint).
	Protocol string `json:"protocol" jsonschema:"title=protocol,description=The transport used to read events from Event Hub: amqp (default) or kafka,enum=amqp,enum=kafka"`
	// Auth selects how the plugin authenticates against Azure.
	Auth AuthConfig `json:"auth" jsonschema:"title=auth,description=Azure authentication configuration"`

	EventHubNamespaceConnectionString string `json:"event_hub_namespace_connection_string" jsonschema:"title=event_hub_namespace_connection_string,description=The connection string of the EventHub Namespace to read from. Required when auth.type is connection_string (the default)"`
	// EventHubNamespace is the fully qualified Event Hub namespace (e.g.
	// my-namespace.servicebus.windows.net). Required for the kafka protocol
	// and for any non-connection-string auth type; when using the kafka
	// protocol with connection_string auth it is derived automatically from
	// EventHubNamespaceConnectionString if left empty.
	EventHubNamespace string `json:"event_hub_namespace" jsonschema:"title=event_hub_namespace,description=The fully qualified EventHub namespace, e.g. my-namespace.servicebus.windows.net"`
	EventHubName      string `json:"event_hub_name" jsonschema:"title=event_hub_name,description=The name of the EventHub to read from"`
	// ConsumerGroup is the Event Hub consumer group used by the amqp
	// protocol, and the Kafka consumer group ID used by the kafka protocol.
	ConsumerGroup string `json:"consumer_group" jsonschema:"title=consumer_group,description=The EventHub consumer group (amqp) or Kafka consumer group id (kafka). Defaults to $Default"`

	BlobStorageConnectionString string `json:"blob_storage_connection_string" jsonschema:"title=blob_storage_connection_string,description=The connection string of the Blob Storage to use as checkpoint store (amqp protocol only). Required when auth.type is connection_string (the default)"`
	// BlobStorageAccountURL is the Blob Storage account endpoint (e.g.
	// https://myaccount.blob.core.windows.net). Only used by the amqp
	// protocol when auth.type is not connection_string; the kafka protocol
	// does not use a Blob Storage checkpoint store.
	BlobStorageAccountURL    string `json:"blob_storage_account_url" jsonschema:"title=blob_storage_account_url,description=The Blob Storage account URL, e.g. https://myaccount.blob.core.windows.net (amqp protocol only, non connection_string auth)"`
	BlobStorageContainerName string `json:"blob_storage_container_name" jsonschema:"title=blob_storage_container_name,description=The name of the Blob Storage container to use as checkpoint store (amqp protocol only)"`

	RateLimitEventsPerSecond int    `json:"rate_limit_events_per_second" jsonschema:"title=rate_limit_events_per_second,description=The rate limit of events per second to read from EventHub"`
	RateLimitBurst           int    `json:"rate_limit_burst" jsonschema:"title=rate_limit_burst,description=The rate limit burst of events to read from EventHub"`
	MaxEventSize             uint64 `json:"maxEventSize"         jsonschema:"title=Maximum event size,description=Maximum size of single audit event (Default: 262144),default=262144"`
}

func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          21,
		Name:        pluginName,
		Description: "Read Kubernetes Audit Events for AKS from EventHub (AMQP or Kafka protocol) and use blob storage as checkpoint store",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.7.0",
		EventSource: "k8s_audit",
	}
}

func (p *PluginConfig) SetDefault() {
	p.RateLimitBurst = 200
	p.RateLimitEventsPerSecond = 100
	p.Protocol = protocolAMQP
	p.ConsumerGroup = azeventhubs.DefaultConsumerGroup
	p.Auth.Type = identity.TypeConnectionString
}

// Resets sets the configuration to its default values
func (k *PluginConfig) Reset() {
	k.MaxEventSize = uint64(sdk.DefaultEvtSize)
}

// validate checks that the combination of protocol and auth type has all
// the configuration it needs, returning a descriptive error otherwise.
func (p *PluginConfig) validate() error {
	switch p.Protocol {
	case protocolAMQP, protocolKafka:
	default:
		return fmt.Errorf("invalid protocol %q: must be %q or %q", p.Protocol, protocolAMQP, protocolKafka)
	}

	switch p.Auth.Type {
	case identity.TypeConnectionString, identity.TypeEnvironment, identity.TypeManagedIdentity, identity.TypeWorkloadIdentity:
	default:
		return fmt.Errorf("invalid auth.type %q", p.Auth.Type)
	}

	if p.EventHubName == "" {
		return fmt.Errorf("event_hub_name is required")
	}

	if p.ConsumerGroup == "" {
		// An empty GroupID doesn't error in the kafka protocol - it just
		// silently switches kafka-go out of consumer-group mode, dropping
		// offset tracking entirely - so reject it explicitly here instead.
		return fmt.Errorf("consumer_group must not be empty")
	}

	usesConnectionString := p.Auth.Type == identity.TypeConnectionString
	if usesConnectionString && p.EventHubNamespaceConnectionString == "" {
		return fmt.Errorf("event_hub_namespace_connection_string is required when auth.type is %q", identity.TypeConnectionString)
	}
	if !usesConnectionString && p.EventHubNamespace == "" {
		return fmt.Errorf("event_hub_namespace is required when auth.type is %q", p.Auth.Type)
	}

	if p.Protocol == protocolAMQP {
		if usesConnectionString && p.BlobStorageConnectionString == "" {
			return fmt.Errorf("blob_storage_connection_string is required when protocol is %q and auth.type is %q", protocolAMQP, identity.TypeConnectionString)
		}
		if !usesConnectionString && p.BlobStorageAccountURL == "" {
			return fmt.Errorf("blob_storage_account_url is required when protocol is %q and auth.type is %q", protocolAMQP, p.Auth.Type)
		}
		if p.BlobStorageContainerName == "" {
			return fmt.Errorf("blob_storage_container_name is required when protocol is %q", protocolAMQP)
		}
	}

	return nil
}

// resolveNamespaceHost returns the fully qualified Event Hubs namespace
// (e.g. "my-namespace.servicebus.windows.net") to dial, used by the kafka
// protocol to build the broker address regardless of auth type. It prefers
// the explicit EventHubNamespace, falling back to parsing the "Endpoint="
// segment out of the connection string.
func (p *PluginConfig) resolveNamespaceHost() (string, error) {
	if p.EventHubNamespace != "" {
		host := strings.TrimSuffix(p.EventHubNamespace, "/")
		if strings.Contains(host, "://") {
			return "", fmt.Errorf("event_hub_namespace must be a bare hostname (e.g. my-namespace.servicebus.windows.net), not a URL: %q", p.EventHubNamespace)
		}
		return host, nil
	}

	// Connection strings look like:
	// Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=...;SharedAccessKey=...
	for _, part := range strings.Split(p.EventHubNamespaceConnectionString, ";") {
		if host, ok := strings.CutPrefix(part, "Endpoint=sb://"); ok {
			return strings.TrimSuffix(host, "/"), nil
		}
	}
	return "", fmt.Errorf("unable to determine the EventHub namespace: set event_hub_namespace or a valid event_hub_namespace_connection_string")
}

func (p *Plugin) Init(cfg string) error {
	p.Config.Reset()
	p.Plugin.Config.Reset()
	p.Config.SetDefault()
	err := json.Unmarshal([]byte(cfg), &p.Config)
	if err != nil {
		return err
	}

	if err := p.Config.validate(); err != nil {
		return err
	}

	// Building the credential here (rather than only in Open()) surfaces
	// missing/incomplete auth configuration - whether given in init_config
	// or expected from the environment - as an Init() error, before Falco
	// starts consuming events.
	if _, err := p.newCredential(); err != nil {
		return fmt.Errorf("invalid auth configuration: %w", err)
	}

	// Propagate MaxEventSize to the embedded k8saudit plugin config
	p.Plugin.Config.MaxEventSize = p.Config.MaxEventSize

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
	if p.Config.Protocol == protocolKafka {
		return p.openKafka()
	}
	return p.openAMQP()
}

// newCredential builds the Azure AD credential for the configured auth
// type, or (nil, nil) when auth.type is connection_string. Any field left
// empty in Config.Auth falls back to the matching AZURE_* environment
// variable; see identity.Config.
func (p *Plugin) newCredential() (azcore.TokenCredential, error) {
	return identity.NewCredential(identity.Config{
		Type:                       p.Config.Auth.Type,
		ManagedIdentityClientID:    p.Config.Auth.ManagedIdentityClientID,
		TenantID:                   p.Config.Auth.TenantID,
		ClientID:                   p.Config.Auth.ClientID,
		ClientSecret:               p.Config.Auth.ClientSecret,
		ClientCertificatePath:      p.Config.Auth.ClientCertificatePath,
		ClientCertificatePassword:  p.Config.Auth.ClientCertificatePassword,
		ClientSendCertificateChain: p.Config.Auth.ClientSendCertificateChain,
	})
}

// runRecordPump starts the goroutine shared by both protocols that drains
// eventsC, unwraps/validates each record's JSON payload, parses it into
// Falco audit events and pushes them onto pushEventC. It returns the
// WaitGroup the caller must Wait() on (after closing eventsC) before
// closing pushEventC.
func (p *Plugin) runRecordPump(ctx context.Context, eventsC <-chan falcoeventhub.Record, pushEventC chan<- source.PushEvent) *sync.WaitGroup {
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
				// AKS diagnostic settings can route categories other than
				// `kube-audit` to the same EventHub (kube-apiserver, kube-controller-manager,
				// cluster-autoscaler, etc.). Those records carry klog text in
				// properties.log instead of a JSON audit event. Pre-validate so
				// the parser does not spam "cannot parse JSON" errors. See issue #1145.
				logBytes := []byte(i.Properties.Log)
				if fastjson.ValidateBytes(logBytes) != nil {
					continue
				}
				values, err := p.Plugin.ParseAuditEventsPayload(logBytes)
				if err != nil {
					p.Logger.Println(err)
					continue
				}
				for _, j := range values {
					if j.Err != nil {
						p.Logger.Println(j.Err)
						continue
					}
					select {
					case pushEventC <- *j:
					case <-ctx.Done():
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return &wg
}
