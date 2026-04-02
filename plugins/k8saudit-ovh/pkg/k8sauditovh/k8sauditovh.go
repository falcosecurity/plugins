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

package k8sauditovh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"

	"github.com/gorilla/websocket"
)

var (
	ID          uint32
	Name        string
	Description string
	Contact     string
	Version     string
	EventSource string
)

const (
	pluginName = "k8saudit-ovh"

	// Time allowed to read the next pong message from the client.
	pongWait = 60 * time.Second

	// Initial wait time before attempting to reconnect after a connection failure.
	reconnectWaitInitial = 1 * time.Second

	// Maximum wait time between reconnection attempts.
	reconnectWaitMax = 60 * time.Second

	// Separator used in the template output between the app ID and the message payload.
	templateSeparator = "> "
)

type PluginConfig struct {
	MaxEventSize uint64 `json:"maxEventSize"         jsonschema:"title=Maximum event size,description=Maximum size of single audit event (Default: 262144),default=262144"`
}

// Plugin represents our plugin
type Plugin struct {
	k8saudit.Plugin
	Logger *log.Logger
	Config PluginConfig
}

// Resets sets the configuration to its default values
func (k *PluginConfig) Reset() {
	k.MaxEventSize = uint64(sdk.DefaultEvtSize)
}

// SetInfo is used to set the Info of the plugin
func (p *Plugin) SetInfo(id uint32, name, description, contact, version, eventSource string) {
	ID = id
	Name = name
	Contact = contact
	Version = version
	EventSource = eventSource
}

// Info displays information of the plugin to Falco plugin framework
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          ID,
		Name:        Name,
		Description: Description,
		Contact:     Contact,
		Version:     Version,
		EventSource: EventSource,
	}
}

// Init is called by the Falco plugin framework as first entry,
// we use it for setting default configuration values and mapping
// values from `init_config` (json format for this plugin)
func (p *Plugin) Init(config string) error {
	p.Plugin.Config.Reset()
	p.Config.Reset()
	if config != "" {
		if err := json.Unmarshal([]byte(config), &p.Config); err != nil {
			return err
		}
	}
	// Propagate MaxEventSize to the embedded k8saudit plugin config
	p.Plugin.Config.MaxEventSize = p.Config.MaxEventSize
	p.Logger = log.New(os.Stderr, "["+pluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	return nil
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{
		{Value: "", Desc: "The LDP Websocket URL to use to get the OVHcloud MKS Audit Logs sent to a LDP data stream"},
	}, nil
}

// isRecoverable determines if a WebSocket dial failure warrants a retry.
// Non-recoverable errors (e.g. auth failures, not found) are returned immediately
// to avoid infinite retry loops on configuration issues.
func isRecoverable(resp *http.Response, err error) bool {
	if err == nil {
		return false
	}

	if resp != nil {
		switch resp.StatusCode {
		case http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
			http.StatusBadRequest:
			return false
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Bad handshake with no response often means a proxy/LB dropped the connection.
	if errors.Is(err, websocket.ErrBadHandshake) && resp == nil {
		return true
	}

	return false
}

// readLoop reads messages from an established WebSocket connection until it breaks.
// Using a dedicated function allows defer to close the connection at the end of
// each connection attempt rather than at the end of the goroutine.
func (p *Plugin) readLoop(wsChan *websocket.Conn, t *template.Template, eventC chan source.PushEvent) {
	defer wsChan.Close()

	for {
		//wsChan.SetReadDeadline(time.Now().Add(5 * time.Second))
		wsChan.SetReadDeadline(time.Now().Add(pongWait))
		_, msg, err := wsChan.ReadMessage()

		// Keep the WebSocket connection alive
		if t, ok := err.(net.Error); ok && t.Timeout() {
			// Timeout, send a Ping && continue
			if err := wsChan.WriteMessage(websocket.PingMessage, nil); err != nil {
				p.Logger.Println("The end host probably closed the connection", err.Error())
				return
			}
			continue
		}

		if err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseGoingAway,
				websocket.CloseAbnormalClosure,
				websocket.CloseNormalClosure) {
				p.Logger.Printf("Unexpected WebSocket close error: %s\n", err.Error())
			}
			return
		}

		// Extract Message
		var logMessage struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(msg, &logMessage); err != nil {
			p.Logger.Printf("Failed to unmarshal log envelope: %s\n", err.Error())
			continue
		}

		// Extract infos
		var message map[string]interface{}
		if err := json.Unmarshal([]byte(logMessage.Message), &message); err != nil {
			p.Logger.Printf("Failed to unmarshal log message: %s\n", err.Error())
			continue
		}

		var m bytes.Buffer
		err = t.Execute(&m, message)
		if err != nil {
			p.Logger.Println(err)
			continue
		}

		// Strip the "{_appID}> " prefix to isolate the audit event payload.
		// strings.SplitN replaces the previous [12:] magic number that assumed a fixed-length appID.
		parts := strings.SplitN(m.String(), templateSeparator, 2)
		if len(parts) != 2 {
			p.Logger.Printf("Unexpected template output, separator %q not found: %q\n", templateSeparator, m.String())
			continue
		}

		// Parse audit events payload thanks to k8saudit extract parse and extract methods
		values, err := p.Plugin.ParseAuditEventsPayload([]byte(parts[1]))
		if err != nil {
			p.Logger.Println(err)
			continue
		}
		for _, j := range values {
			if j.Err != nil {
				p.Logger.Println(j.Err)
				continue
			}

			eventC <- *j
		}
	}
}

// Open is called by Falco plugin framework for opening a stream of events, we call that an instance
func (p *Plugin) Open(ovhLDPURL string) (source.Instance, error) {
	t, err := template.New("template").Funcs(template.FuncMap{
		"color":    color,
		"bColor":   bColor,
		"noColor":  func() string { return color("reset") },
		"date":     date,
		"join":     join,
		"concat":   concat,
		"duration": duration,
		"int":      toInt,
		"float":    toFloat,
		"string":   toString,
		"get":      get,
		"column":   column,
		"begin":    begin,
		"contain":  contain,
		"level":    level,
	}).Parse("{{._appID}}> {{.short_message}}")
	if err != nil {
		p.Logger.Fatalf("Failed to parse pattern: %s", err.Error())
	}

	if ovhLDPURL == "" {
		return nil, fmt.Errorf("OVHcloud LDP URL can't be empty")
	}

	eventC := make(chan source.PushEvent)

	go func() {
		defer close(eventC)

		u := url.URL{Scheme: "wss", Host: ovhLDPURL, Path: ""}
		v, _ := url.QueryUnescape(u.String())

		headers := make(http.Header)
		// headers.Set("Origin", "http://mySelf")

		// Exponential backoff for reconnection attempts.
		wait := reconnectWaitInitial

		// Outer reconnect loop: if the connection drops, we dial again instead of exiting.
		for {
			wsChan, resp, err := websocket.DefaultDialer.Dial(v, headers)
			if err != nil {
				if !isRecoverable(resp, err) {
					p.Logger.Printf("Non-recoverable error connecting to %q: %s. Stopping.\n", u.Host, err.Error())
					eventC <- source.PushEvent{Err: err}
					return
				}
				p.Logger.Printf("Failed to connect to %q: %s. Will retry after %s...\n", u.Host, err.Error(), wait)
				time.Sleep(wait)
				wait *= 2
				if wait > reconnectWaitMax {
					wait = reconnectWaitMax
				}
				continue
			}

			// Reset backoff on successful connection.
			wait = reconnectWaitInitial
			p.Logger.Printf("Connected to %q\n", u.Host)

			p.readLoop(wsChan, t, eventC)

			p.Logger.Printf("Disconnected from %q. Will try to reconnect after %s...\n", u.Host, wait)
			time.Sleep(wait)
		}
	}()
	return source.NewPushInstance(
		eventC,
		source.WithInstanceEventSize(uint32(p.Config.MaxEventSize)),
	)
}
