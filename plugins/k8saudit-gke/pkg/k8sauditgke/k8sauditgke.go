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
	"fmt"
	"os"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/option"
)

const (
	PluginID          uint32 = 16
	PluginName               = "k8saudit-gke"
	PluginDescription        = "Read Kubernetes Audit Events for GKE from a Pub/Sub subscription"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.1.1"
	PluginEventSource        = "k8s_audit"
)

func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) Open(params string) (source.Instance, error) {
	if params == "" {
		return nil, fmt.Errorf("no subscriptionID provided")
	}

	// Read audit logs from file, instead of PubSub subscription, for debugging purposes
	subscriptionID := params
	if strings.HasPrefix(subscriptionID, "file://") {
		return p.newFileReaderInstance(strings.TrimPrefix(subscriptionID, "file://"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	eventsC, errC := p.pullMsgsSync(ctx, subscriptionID)

	pushEventC := make(chan source.PushEvent)
	go func() {
		defer close(pushEventC)
		for {
			select {
			case event := <-eventsC:
				pushEventC <- event
			case e := <-errC:
				pushEventC <- source.PushEvent{Err: e}
				return
			}
		}
	}()

	return source.NewPushInstance(pushEventC, source.WithInstanceClose(cancel))
}

func (p *Plugin) newFileReaderInstance(file string) (source.Instance, error) {
	trimmed := strings.TrimSpace(file)
	fileInfo, err := os.Stat(trimmed)
	if err != nil {
		return nil, err
	}
	if !fileInfo.IsDir() {
		return p.OpenReader(trimmed)
	}
	return nil, fmt.Errorf("path is not a file")
}

func (k *Plugin) OpenReader(r string) (source.Instance, error) {
	evtC := make(chan source.PushEvent)

	go func() {
		defer close(evtC)

		b, err := os.ReadFile(r)
		if err != nil {
			evtC <- source.PushEvent{Err: err}
		}
		evtC <- source.PushEvent{Data: b}
	}()

	return source.NewPushInstance(
		evtC,
		source.WithInstanceEventSize(uint32(k.Config.MaxEventSize)))
}

func (p *Plugin) NewContainerService(ctx context.Context) (*container.Service, error) {
	var clientOptions []option.ClientOption
	if len(p.Config.CredentialsFile) > 0 {
		clientOptions = append(clientOptions, option.WithCredentialsFile(p.Config.CredentialsFile))
	}

	return container.NewService(ctx, clientOptions...)
}
