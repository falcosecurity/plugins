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

package github

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/google/go-github/github"
	"github.com/valyala/fastjson"
	"golang.org/x/oauth2"
)

const (
	PluginID           uint32 = 8
	PluginName                = "github"
	PluginDescription         = "Reads github webhook events, by listening on a socket or by reading events from disk"
	PluginContact             = "github.com/falcosecurity/plugins"
	PluginVersion             = "0.6.0"
	PluginEventSource         = "github"
	ExtractEventSource        = "github"
)

type diffMatchInfo struct {
	Line     uint64 `json:"line"`
	Type     string `json:"type"`
	Desc     string `json:"desc"`
	Platform string `json:"platform"`
}

type diffFileInfo struct {
	FileName string          `json:"name"`
	Matches  []diffMatchInfo `json:"matches"`
}

type workflowFileInfo struct {
	FileName     string               `json:"name"`
	MinerMatches []minerDetectionInfo `json:"matches"`
}

type minerDetectionInfo struct {
	Line uint64 `json:"line"`
	Type string `json:"type"`
}

type oauthContext struct {
	token string
	ctx   context.Context
	ts    oauth2.TokenSource
	tc    *http.Client
}

type githubHookInfo struct {
	owner string
	repo  string
	id    int64
}

// Plugin represent the GithHub plugin
type Plugin struct {
	plugins.BasePlugin
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	config      PluginConfig
}

// PluginInstance represents an opened instance of the plugin,
// which is returned by Open() and deinitialized during Close().
type PluginInstance struct {
	source.BaseInstance
	whURL          string
	whSrv          *http.Server
	whSrvChan      chan []byte
	whSecret       string
	ghOauth        oauthContext
	installedHooks []githubHookInfo
	ghClient       *github.Client
}

// Return the plugin info to the framework.
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  PluginID,
		Name:                PluginName,
		Description:         PluginDescription,
		Contact:             PluginContact,
		Version:             PluginVersion,
		EventSource:         PluginEventSource,
		ExtractEventSources: []string{ExtractEventSource},
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

// Initialize the plugin state.
func (p *Plugin) Init(cfg string) error {
	// initialize state
	p.jdataEvtnum = math.MaxUint64

	// Set config default values and read the passed one, if available.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.config.Reset()
	json.Unmarshal([]byte(cfg), &p.config)

	// If there's a ~ at the beginning of the secrets directory, try to resolve it to make life easier for the user
	secretsDir := p.config.SecretsDir
	if len(secretsDir) > 0 && secretsDir[0] == '~' {
		homeDir, _ := os.UserHomeDir()
		secretsDir = homeDir + p.config.SecretsDir[1:]
	}
	p.config.SecretsDir = secretsDir

	// enable/disable async extraction optimazion (enabled by default)
	extract.SetAsync(p.config.UseAsync)
	return nil
}
