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

package hashicorpvault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/gorilla/websocket"
)

// Events are arbitrary, non-secret data that can be exchanged between producers (Vault and plugins)
// and subscribers (Vault components and external users via the API)
type Event struct {
	ID              string `json:"id"`
	Time            string `json:"time"`
	DataContentType string `json:"datacontentype"`
	Type            string `json:"type"`
	Data            struct {
		Event struct {
			ID       string `json:"id"`
			Metadata struct {
				CurrentVersion string `json:"current_version"`
				OldestVersion  string `json:"oldest_version"`
				Path           string `json:"path"`
			} `json:"metadata"`
		} `json:"event"`
		EventType  string `json:"event_type"`
		PluginInfo struct {
			MountClass    string `json:"mount_class"`
			MountAccessor string `json:"mount_accessor"`
			MountPath     string `json:"mount_path"`
			Plugin        string `json:"plugin"`
		} `json:"plugin_info"`
	} `json:"data"`
}

// Plugin represents our plugin
type Plugin struct {
	plugins.BasePlugin
	Token        string `json:"token" jsonschema:"title=Token,description=Token"`
	HostPort     string `json:"host_port" jsonschema:"title=HostPort,description=Host:Port"`
	lastEvent    Event
	lastEventNum uint64
}

// PluginInstance represents a opened stream based on our Plugin
type PluginInstance struct {
	source.BaseInstance
	cancel context.CancelFunc
}

const vaultBasePath string = "/v1/sys/events/subscribe/*?json=true"

// Info displays information of the plugin to Falco plugin framework
func (hashicorpvaultPlugin *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          11,
		Name:        "hashicorp-vault",
		Description: "Hashicorp Vault Events",
		Contact:     "github.com/falcosecurity/plugins/",
		Version:     "0.1.0",
		EventSource: "hashicorpvault",
	}
}

// InitSchema exports the json schema for parameters
func (hashicorpvaultPlugin *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&Plugin{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (hashicorpvaultPlugin *Plugin) Init(config string) error {
	err := json.Unmarshal([]byte(config), &hashicorpvaultPlugin)
	if err != nil {
		return err
	}
	return nil
}

// Fields exposes to Falco plugin framework all availables fields for this plugin
func (hashicorpvaultPlugin *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "hashicorpvault.event.id", Desc: "CloudEvents unique identifier for the event"},
		{Type: "string", Name: "hashicorpvault.event.type", Desc: "The event type that was published"},
		{Type: "string", Name: "hashicorpvault.metadata.currentversion", Desc: "Current version of the object"},
		{Type: "string", Name: "hashicorpvault.metadata.oldestversion", Desc: "Oldest version of the object"},
		{Type: "string", Name: "hashicorpvault.metadata.path", Desc: "Path of the object"},
		{Type: "string", Name: "hashicorpvault.plugin.mountclass", Desc: "The class of the plugin"},
		{Type: "string", Name: "hashicorpvault.plugin.mountaccessor", Desc: "The unique ID of the mounted plugin"},
		{Type: "string", Name: "hashicorpvault.plugin.mountpath", Desc: "The path that the plugin is mounted at"},
		{Type: "string", Name: "hashicorpvault.plugin.name", Desc: "The name of the plugin"},
	}
}

// Extract allows Falco plugin framework to get values for all available fields
func (hashicorpvaultPlugin *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	event := hashicorpvaultPlugin.lastEvent

	if evt.EventNum() != hashicorpvaultPlugin.lastEventNum {
		rawData, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		err = json.Unmarshal(rawData, &event)
		if err != nil {
			return err
		}

		hashicorpvaultPlugin.lastEvent = event
		hashicorpvaultPlugin.lastEventNum = evt.EventNum()
	}

	switch req.Field() {
	case "hashicorpvault.event.id":
		req.SetValue(event.Data.Event.ID)
	case "hashicorpvault.event.type":
		req.SetValue(event.Data.EventType)
	case "hashicorpvault.metadata.currentversion":
		req.SetValue(event.Data.Event.Metadata.CurrentVersion)
	case "hashicorpvault.metadata.oldestversion":
		req.SetValue(event.Data.Event.Metadata.OldestVersion)
	case "hashicorpvault.metadata.path":
		req.SetValue(event.Data.Event.Metadata.Path)
	case "hashicorpvault.plugin.mountclass":
		req.SetValue(event.Data.PluginInfo.MountClass)
	case "hashicorpvault.plugin.mountaccessor":
		req.SetValue(event.Data.PluginInfo.MountAccessor)
	case "hashicorpvault.plugin.mountpath":
		req.SetValue(event.Data.PluginInfo.MountPath)
	case "hashicorpvault.plugin.name":
		req.SetValue(event.Data.PluginInfo.Plugin)
	default:
		return nil
	}

	return nil
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (hashicorpvaultPlugin *Plugin) Open(params string) (source.Instance, error) {
	eventC := make(chan source.PushEvent)
	ctx, cancel := context.WithCancel(context.Background())

	// launch an async worker that listens for Docker events and pushes them
	// to the event channel
	go func() {
		defer close(eventC)

		headers := make(http.Header)
		headers.Add("X-Vault-Token", hashicorpvaultPlugin.Token)

		u := url.URL{Scheme: "ws", Host: hashicorpvaultPlugin.HostPort, Path: vaultBasePath}
		v, _ := url.QueryUnescape(u.String())

		wsclient, _, err := websocket.DefaultDialer.DialContext(ctx, v, headers)
		if err != nil {
			eventC <- source.PushEvent{Err: err}
			// errors are blocking, so we can stop here
			return
		}
		defer wsclient.Close()

		for {
			_, message, err := wsclient.ReadMessage()
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			eventBytes, err := json.Marshal(message)
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			eventBase64 := strings.ReplaceAll(string(eventBytes), `"`, "")
			event, err := base64.StdEncoding.DecodeString(eventBase64)
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			eventC <- source.PushEvent{Data: []byte(event)}
		}
	}()

	return source.NewPushInstance(eventC, source.WithInstanceClose(cancel))
}

// String represents the raw value of on event
// todo: optimize this to cache by event number
func (hashicorpvaultPlugin *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}

func (haschicorpvaultInstance *PluginInstance) Close() {
	haschicorpvaultInstance.cancel()
}
