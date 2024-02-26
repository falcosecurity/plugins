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

package k8sauditgke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	logging "cloud.google.com/go/logging/apiv2/loggingpb"
	"cloud.google.com/go/pubsub"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/cloud/audit"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func (p *Plugin) pullMsgsSync(ctx context.Context, subscriptionID string) (chan source.PushEvent, chan error) {
	var clientOptions []option.ClientOption
	if len(p.Config.CredentialsFile) > 0 {
		clientOptions = append(clientOptions, option.WithCredentialsFile(p.Config.CredentialsFile))
	}

	errC := make(chan error)
	eventC := make(chan source.PushEvent)
	go func() {
		defer close(eventC)
		defer close(errC)

		// create pubsub client
		client, err := pubsub.NewClient(ctx, p.Config.ProjectID, clientOptions...)
		if err != nil {
			errC <- err
			return
		}

		// attempt subscribing with exponential backoff
		sub := client.Subscription(subscriptionID)
		sub.ReceiveSettings.MaxOutstandingMessages = p.Config.MaxOutstandingMessages
		sub.ReceiveSettings.NumGoroutines = p.Config.NumGoroutines
		maxRetries := 3
		retryDelay := time.Second
		for retries := 0; retries < maxRetries; retries++ {
			err = p.performPubSubOperation(sub, ctx, eventC)
			if err == nil {
				// Operation succeeded, break out of the loop
				return
			} else if isQuotaExceededError(err) {
				// Quota exceeded, wait for backoff duration and retry
				p.logger.Printf("pubsub receive quota exceeded, retrying in %s\n", retryDelay.String())
				time.Sleep(retryDelay)
				retryDelay *= 2 // exponential backoff
			} else {
				errC <- err
				return
			}
		}
	}()

	return eventC, errC
}

func isQuotaExceededError(err error) bool {
	return strings.Contains(err.Error(), "quota exceeded")
}

func (p *Plugin) performPubSubOperation(subscription *pubsub.Subscription, ctx context.Context, eventC chan source.PushEvent) error {
	return subscription.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		defer msg.Ack()

		logEntry := &logging.LogEntry{}
		err := protojson.Unmarshal(msg.Data, logEntry)
		if err != nil {
			p.logger.Printf("failed to unmarshal PubSub message to log entry: %v\n", err)
			return
		}

		if !isValidLogEntry(logEntry) {
			p.logger.Printf("dropped unrecognised log entry (insertId=%s)\n", logEntry.InsertId)
			return
		}

		switch payload := logEntry.Payload.(type) {
		case *logging.LogEntry_ProtoPayload:
			switch payload.ProtoPayload.TypeUrl {
			case "type.googleapis.com/google.cloud.audit.AuditLog":
				auditLog := &audit.AuditLog{}
				err := proto.UnmarshalOptions{DiscardUnknown: false}.Unmarshal(payload.ProtoPayload.Value, auditLog)
				if err != nil {
					p.logger.Printf("failed to unmarshal log entry payload (insertId=%s): %v\n", logEntry.InsertId, err)
					return
				}

				// Check audit log service name
				if auditLog.ServiceName != "k8s.io" {
					p.logger.Printf("dropped log entry with unrecognised service name (insertId=%s)\n", logEntry.InsertId)
					return
				}

				event, err := p.processAuditLogEntry(logEntry, auditLog)
				if err != nil {
					p.logger.Printf("failed to process log entry (insertId=%s): %v\n", logEntry.InsertId, err)
					return
				}

				eventC <- *event
			default:
				p.logger.Printf("unsupported payload type: %s", payload.ProtoPayload.TypeUrl)
				return
			}
		}
	})
}

func isValidLogEntry(logEntry *logging.LogEntry) bool {
	// Check whether or not this is an audit log entry at all
	if !(strings.HasSuffix(logEntry.LogName, "cloudaudit.googleapis.com%2Factivity") ||
		strings.HasSuffix(logEntry.LogName, "cloudaudit.googleapis.com%2Fdata_access")) {
		return false
	}

	// Check whether or not this is a GKE audit log entry
	return logEntry.Resource.Type == "k8s_cluster"
}

func (p *Plugin) processAuditLogEntry(logEntry *logging.LogEntry, auditLog *audit.AuditLog) (*source.PushEvent, error) {
	// Get cluster labels from Container API (or cache), if enabled
	if p.Config.FetchClusterMetadata {
		metadataLabels, err := p.getClusterLabels(logEntry.Resource)
		if err != nil {
			// Just continue processing the log entry without cluster labels
			p.logger.Printf("%v", err)
		} else {
			for lbl, lblValue := range metadataLabels {
				// Do not override Google defined resource labels
				if lbl != "cluster_name" && lbl != "location" && lbl != "project_id" {
					logEntry.Resource.Labels[lbl] = lblValue
				}
			}
		}
	}

	event, err := p.convertLogEntry(logEntry, auditLog)
	if err != nil {
		return nil, fmt.Errorf("failed to convert log entry: %v", err)
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal k8s audit event: %v", err)
	}

	if len(eventJSON) > int(p.Config.MaxEventSize) {
		return nil, fmt.Errorf("event larger than maxEventSize: size=%d", len(eventJSON))
	}

	pushEvent := &source.PushEvent{
		Timestamp: event.RequestReceivedTimestamp.Time,
		Data:      eventJSON,
	}
	return pushEvent, nil
}

func (p *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := io.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)
	return fmt.Sprintf("%v", evtStr), nil
}
