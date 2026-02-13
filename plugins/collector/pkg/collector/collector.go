// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 24
	PluginName               = "collector"
	PluginDescription        = "Generic collector to ingest raw payloads"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.1.1"
	PluginEventSource        = "collector"
)

type PluginOpenParams struct {
	Buffer uint64 `json:"buffer" jsonschema:"title=Payloads buffer,description=Number of payloads held by the buffer (Default: 0),default=0"`
	Addr   string `json:"addr" jsonschema:"title=Listen address,description=The TCP address for the server to listen on in the form host:port (Default: :54827),default=:54827"`
}

type Plugin struct {
	plugins.BasePlugin
	// Contains the open params configuration
	openParams PluginOpenParams
}

func (p *PluginOpenParams) setDefault() {
	p.Buffer = 0
	p.Addr = ":54827"
}

func (m *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) Init(cfg string) error {
	return nil
}

func (p *Plugin) Open(prms string) (source.Instance, error) {

	p.openParams.setDefault()
	if len(prms) != 0 {
		if err := json.Unmarshal([]byte(prms), &p.openParams); err != nil {
			return nil, fmt.Errorf("wrong open params format: %s", err.Error())
		}
	}

	evtC := make(chan source.PushEvent, p.openParams.Buffer)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := io.ReadAll(r.Body)
		defer r.Body.Close()

		pushEvt := source.PushEvent{
			Err:  err,
			Data: data,
		}

		evtC <- pushEvt
	})

	server := &http.Server{
		Addr:    p.openParams.Addr,
		Handler: mux,
	}

	go (func() {
		if err := server.ListenAndServe(); err != nil {
			pushEvt := source.PushEvent{
				Err: fmt.Errorf("failed to start server: %v", err),
			}
			evtC <- pushEvt
		}
	})()

	return source.NewPushInstance(
		evtC,
		source.WithInstanceClose(func() {
			if err := server.Close(); err != nil {
				pushEvt := source.PushEvent{
					Err: fmt.Errorf("failed to stop server: %v", err),
				}
				evtC <- pushEvt
			}
		}),
	)
}

func (m *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := io.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	// The string representation of an event is the raw payload
	return string(evtBytes), nil
}
