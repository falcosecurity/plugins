package k8sauditovh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
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
	p.Logger = log.New(os.Stderr, "["+pluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	return nil
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{
		{Value: "", Desc: "The LDP Websocket URL to use to get the OVHcloud MKS Audit Logs sent to a LDP data stream"},
	}, nil
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
		wsChan, _, err := websocket.DefaultDialer.Dial(v, headers)
		if err != nil {
			eventC <- source.PushEvent{Err: err}
			return
		}
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
				}
				continue
			}

			if err != nil {
				p.Logger.Printf("Error while reading from %q: %q. Will try to reconnect after 1s...\n", u.Host, err.Error())
				time.Sleep(1 * time.Second)
				break
			}

			// Extract Message
			var logMessage struct {
				Message string `json:"message"`
			}
			json.Unmarshal(msg, &logMessage)

			// Extract infos
			var message map[string]interface{}
			json.Unmarshal([]byte(logMessage.Message), &message)

			var m bytes.Buffer
			err = t.Execute(&m, message)
			if err != nil {
				p.Logger.Println(err)
				continue
			}

			// Parse audit events payload thanks to k8saudit extract parse and extract methods
			values, err := p.Plugin.ParseAuditEventsPayload([]byte(m.String())[12:])
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
	}()
	return source.NewPushInstance(eventC)
}
