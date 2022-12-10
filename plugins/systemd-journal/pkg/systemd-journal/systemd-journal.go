/*
Copyright (C) 2022 The Falco Authors.

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

package systemd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"strconv"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/valyala/fastjson"
)

const (
	PluginID          uint32 = 11
	PluginName               = "systemd-journal"
	PluginDescription        = "Reads events from the systemd journal"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.1.0"
	PluginEventSource        = "systemd"
)

const (
	MaxEvtSize = 65636
)

type PluginConfig struct {
	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter.
	Lines uint64 `json:"lines" jsonschema:"title=lines,description=number of old lines to show from the log (Default: 0, which means only new lines are shown),default=0"`
}

type Plugin struct {
	plugins.BasePlugin
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	// Contains the init configuration values
	config PluginConfig
}

var supportedFields = []sdk.FieldEntry{
	{Type: "string", Name: "sj.hostname", Display: "Host Name", Desc: "."},
	{Type: "string", Name: "sj.comm", Display: "Comm", Desc: "."},
	{Type: "string", Name: "sj.pid", Display: "PID", Desc: ".", Properties: []string{"conversation"}},
	{Type: "string", Name: "sj.message", Display: "Message", Desc: "."},
}

func (p *PluginConfig) setDefault() {
	p.Lines = 0
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

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (p *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	var res []sdk.OpenParam
	min := 10
	max := int(1e6)
	for min <= max {
		res = append(res, sdk.OpenParam{
			Value: fmt.Sprintf("%d", min),
			Desc:  fmt.Sprintf("Generates a maximum of %d events", min),
		})
		min *= 10
	}
	return res, nil
}

func (p *Plugin) Init(cfg string) error {
	// The format of cfg is a json object with a single param
	// "jitter", e.g. {"jitter": 10}
	// Empty configs are allowed, in which case the default is used.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.config.setDefault()
	json.Unmarshal([]byte(cfg), &p.config)

	return nil
}

func (p *Plugin) Destroy() {
	// nothing to do here
}

func (p *Plugin) Open(prms string) (source.Instance, error) {
	evtC := make(chan source.PushEvent)

	// run the `journalctl` command asyncrhonously
	cmd := exec.Command("journalctl", "-ojson", "-n"+strconv.FormatUint(p.config.Lines, 10), "--follow")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	// Start the goroutine that will listen to the journalctl output and push
	// the events to Falco
	go ReadData(evtC, cmd, stdout)

	// Register this as a push open instance, which means we won't need a next
	return source.NewPushInstance(
		evtC,
		source.WithInstanceEventSize(MaxEvtSize))
}

func ReadData(evtC chan source.PushEvent, cmd *exec.Cmd, stdout io.ReadCloser) {
	var parser fastjson.Parser
	defer close(evtC)

	// Start the command in a goroutine so it runs asynchronously
	go func() {
		if err := cmd.Start(); err != nil {
			fmt.Println("Error running journalctl:", err)
		}
	}()

	// Use a scanner to read the command's output line by line
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		jdata, err := parser.Parse(line)
		if err != nil {
			evtC <- source.PushEvent{Err: err}
			return
		}
		var ts time.Time
		jtss := jdata.GetStringBytes("__REALTIME_TIMESTAMP")
		if jtss != nil {
			nts, err := strconv.ParseInt(string(jtss), 10, 64)
			if err == nil {
				ts = time.Unix(nts/1000000, (nts%1000000)*1000)
			}
		}

		evtC <- source.PushEvent{Data: []byte(line), Timestamp: ts}
	}

	err := scanner.Err()
	if err != nil {
		evtC <- source.PushEvent{Err: err}
	}
}

// todo: optimize this to cache by event number
func (m *Plugin) String(evt sdk.EventReader) (string, error) {
	reader := evt.Reader()

	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != m.jdataEvtnum {
		_, err := reader.Seek(0, io.SeekStart)
		if err != nil {
			return "", err
		}

		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return "", err
		}

		// Try to parse the data as json
		m.jdata, err = m.jparser.ParseBytes(data)
		if err != nil {
			return "", err
		}
		m.jdataEvtnum = evt.EventNum()
	}

	host := m.jdata.GetStringBytes("_HOSTNAME")
	comm := m.jdata.GetStringBytes("_COMM")
	pid := m.jdata.GetStringBytes("_PID")
	message := m.jdata.GetStringBytes("MESSAGE")

	return fmt.Sprintf("%s %s[%s]: %s", host, comm, pid, message), nil
}

func (m *Plugin) Fields() []sdk.FieldEntry {
	return supportedFields
}

func (m *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	reader := evt.Reader()

	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != m.jdataEvtnum {
		_, err := reader.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return err
		}

		// Try to parse the data as json
		m.jdata, err = m.jparser.ParseBytes(data)
		if err != nil {
			return err
		}
		m.jdataEvtnum = evt.EventNum()
	}

	switch req.FieldID() {
	case 0: // sj.hostname
		req.SetValue(string(m.jdata.GetStringBytes("_HOSTNAME")))
	case 1: // sj.comm
		req.SetValue(string(m.jdata.GetStringBytes("_COMM")))
	case 2: // sj.pid
		req.SetValue(string(m.jdata.GetStringBytes("_PID")))
	case 3: // sj.message
		req.SetValue(string(m.jdata.GetStringBytes("MESSAGE")))
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}
