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
	"log"
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

// Plugin info required by the framework.
const (
	PluginID           uint32 = 8
	PluginName                = "github"
	PluginDescription         = "reads github webhook events, by listening on a socket or by reading events from disk"
	PluginContact             = "github.com/falcosecurity/plugins"
	PluginVersion             = "0.1.0"
	PluginEventSource         = "github"
	ExtractEventSource        = "github"
)

const (
	// If set to true, the plugin logs debug information.
	verbose bool = false

	// If set to true, by default the plugin will use async plugin extraction.
	defaultUseAsync bool = false
)

// Struct for plugin init config
type pluginInitConfig struct {
	Token              string `json:"token" jsonschema:"description=The github personal access token to use. You can create a token at this page: https://github.com/settings/tokens. The token needs full repo scope."`
	WebsocketServerURL string `json:"websocketServerURL" jsonschema:"description=The URL of the server where the plugin will run, i.e. the plublic accessible address of this machine."`
	SecretsDir         string `json:"secretsDir" jsonschema:"The directory where the secrets required by the plugin are stored. Unless the github token is provided by environment variable, it must be stored in a file named github.token in this directory. In addition, when the webhook server uses HTTPs, server.key and server.crt must be in this directory too. (Default: ~/.ghplugin)"`
	UseHTTPs           bool   `json:"useHTTPs" jsonschema:"if this parameter is set to true, then the webhook webserver listening at WebsocketServerURL will use HTTPs. In that case, server.key and server.crt must be present in the SecretsDir directory, or the plugin will fail to load. If the parameter is set to false, the webhook webserver will be plain HTTP. Use HTTP only for testing or when the plugin is behind a proxy that handles encryption."`
	UseAsync           bool   `json:"useAsync" jsonschema:"description=If true then async extraction optimization is enabled. (Default: false)"`
}

func (p *pluginInitConfig) setDefault() {
	homeDir, _ := os.UserHomeDir()
	p.SecretsDir = homeDir + "/.ghplugin"
	p.UseHTTPs = true
	p.UseAsync = false
}

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

// This represent the plugin itself.
type pluginContext struct {
	plugins.BasePlugin
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	config      pluginInitConfig
}

// This represents an opened instance of the plugin,
// which is returned by Open() and deinitialized during Close().
type openContext struct {
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
func (p *pluginContext) Info() *plugins.Info {
	log.Printf("[%s] Info\n", PluginName)
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

func (p *pluginContext) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}

	if schema, err := reflector.Reflect(&pluginInitConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}

	return nil
}

// Initialize the plugin state.
func (p *pluginContext) Init(cfg string) error {
	log.Printf("[%s] Init, params=%s\n", PluginName, cfg)

	// initialize state
	p.jdataEvtnum = math.MaxUint64

	// Set config default values and read the passed one, if available.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.config.setDefault()
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
