// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package gcpaudit

import (
	"context"
	"fmt"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 12
	PluginName               = "gcpaudit"
	PluginDescription        = "Read GCP Audit Logs"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.3.0"
	PluginEventSource        = "gcp_auditlog"
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

	subscriptionID := params
	ctx, cancel := context.WithCancel(context.Background())
	eventsC, errC := p.pullMsgsSync(ctx, subscriptionID)

	pushEventC := make(chan source.PushEvent)
	go func() {
		defer close(eventsC)
		for {
			select {
			case messages := <-eventsC:
				pushEventC <- source.PushEvent{Data: messages}

			case e := <-errC:
				pushEventC <- source.PushEvent{Err: e}
				return
			}
		}
	}()

	return source.NewPushInstance(pushEventC, source.WithInstanceClose(cancel))
}
