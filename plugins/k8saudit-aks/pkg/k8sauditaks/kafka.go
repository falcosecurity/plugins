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
	"crypto/tls"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	falcoeventhub "github.com/falcosecurity/plugins/shared/go/azure/eventhub"
	"github.com/falcosecurity/plugins/shared/go/azure/identity"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"golang.org/x/time/rate"
)

const kafkaPort = "9093"

// openKafka consumes the EventHub over its Kafka-compatible endpoint.
// Event Hubs itself tracks Kafka consumer-group offsets, so unlike
// openAMQP this path needs no Blob Storage checkpoint store.
func (p *Plugin) openKafka() (source.Instance, error) {
	ctx, cancel := context.WithCancel(context.Background())

	namespaceHost, err := p.Config.resolveNamespaceHost()
	if err != nil {
		cancel()
		return nil, err
	}
	broker := fmt.Sprintf("%s:%s", namespaceHost, kafkaPort)

	mechanism, err := p.newKafkaSASLMechanism(namespaceHost)
	if err != nil {
		cancel()
		return nil, err
	}

	dialer := &kafkago.Dialer{
		TLS:           &tls.Config{MinVersion: tls.VersionTLS12},
		SASLMechanism: mechanism,
	}

	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:     []string{broker},
		GroupID:     p.Config.ConsumerGroup,
		GroupTopics: []string{p.Config.EventHubName},
		Dialer:      dialer,
	})
	p.Logger.Printf("opened kafka reader for broker %s, topic %s", broker, p.Config.EventHubName)

	rateLimiter := rate.NewLimiter(rate.Limit(p.Config.RateLimitEventsPerSecond), p.Config.RateLimitBurst)
	falcoEventHubProcessor := falcoeventhub.Processor{
		RateLimiter: rateLimiter,
		Logger:      p.Logger,
	}

	eventsC := make(chan falcoeventhub.Record)
	pushEventC := make(chan source.PushEvent)

	// A single goroutine owns eventsC end-to-end: it is the only writer, so
	// it is also the one that closes it once reads stop (on Close or on a
	// terminal read error), avoiding any close/write race.
	go func() {
		defer close(eventsC)
		for {
			msg, err := reader.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() == nil {
					p.Logger.Printf("error reading kafka message: %v", err)
				}
				return
			}
			if err := falcoEventHubProcessor.HandleEvent(ctx, msg.Value, eventsC); err != nil {
				p.Logger.Printf("error handling kafka message: %v", err)
			}
		}
	}()

	wg := p.runRecordPump(ctx, eventsC, pushEventC)

	return source.NewPushInstance(
		pushEventC,
		source.WithInstanceClose(func() {
			cancel()
			if err := reader.Close(); err != nil {
				p.Logger.Printf("error closing kafka reader: %v", err)
			}
			wg.Wait()
			close(pushEventC)
		}),
		source.WithInstanceEventSize(uint32(p.Config.MaxEventSize)),
	)
}

// newKafkaSASLMechanism builds the SASL mechanism to authenticate against
// the Event Hubs Kafka endpoint: SASL/PLAIN with the namespace connection
// string (Azure's documented convention, username "$ConnectionString"), or
// SASL/OAUTHBEARER with an Azure AD access token for the other auth types.
//
// The OAUTHBEARER token's scope must be the namespace's own host
// (https://<namespace>.servicebus.windows.net/.default) — not the generic
// https://eventhubs.azure.net/.default resource AMQP clients use. Event
// Hubs' Kafka head checks the token's audience against the namespace it
// was issued for, so the generic resource is accepted for a token *request*
// but the token itself then fails Kafka's audience check at connect time.
// See Azure's own Kafka OAuth sample, which sets AAD_AUDIENCE to the
// namespace host: https://github.com/Azure/azure-event-hubs-for-kafka/blob/master/tutorials/oauth/go/README.md
func (p *Plugin) newKafkaSASLMechanism(namespaceHost string) (sasl.Mechanism, error) {
	if p.Config.Auth.Type == identity.TypeConnectionString {
		return plain.Mechanism{
			Username: "$ConnectionString",
			Password: p.Config.EventHubNamespaceConnectionString,
		}, nil
	}

	cred, err := p.newCredential()
	if err != nil {
		return nil, err
	}
	scope := kafkaOAuthScope(namespaceHost)
	return oauthBearerMechanism{
		TokenProvider: func(ctx context.Context) (string, error) {
			tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
			if err != nil {
				return "", err
			}
			return tok.Token, nil
		},
	}, nil
}

// kafkaOAuthScope returns the OAuth scope to request a token for, to
// authenticate against the Event Hubs Kafka endpoint at namespaceHost. This
// must be the namespace's own host, not a fixed Event Hubs resource: Event
// Hubs' Kafka head validates the token's audience against the namespace it
// was issued for.
func kafkaOAuthScope(namespaceHost string) string {
	return fmt.Sprintf("https://%s/.default", namespaceHost)
}
