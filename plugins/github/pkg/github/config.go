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
	"os"
	"path/filepath"
)

// PluginConfig represents a configuration of the GitHub plugin
type PluginConfig struct {
	Token              string `json:"token" jsonschema:"title=Personal access token,description=The GitHub personal access token to use. You can create a token at this page: https://github.com/settings/tokens. The token needs full repo scope."`
	WebsocketServerURL string `json:"websocketServerURL" jsonschema:"title=WebSocket server URL,description=The URL of the server where the plugin will run, i.e. the public accessible address of this machine."`
	SecretsDir         string `json:"secretsDir" jsonschema:"title=Secrets directory,description=The directory where the secrets required by the plugin are stored. Unless the github token is provided by environment variable, it must be stored in a file named github.token in this directory. In addition, when the webhook server uses HTTPs, server.key and server.crt must be in this directory too. (Default: ~/.ghplugin),default=~/.ghplugin"`
	UseHTTPs           bool   `json:"useHTTPs" jsonschema:"title=Use HTTPS,description=if this parameter is set to true, then the webhook webserver listening at WebsocketServerURL will use HTTPS. In that case, server.key and server.crt must be present in the secrets directory, or the plugin will fail to load. If the parameter is set to false, the webhook webserver will be plain HTTP. Use HTTP only for testing or when the plugin is behind a proxy that handles encryption."`
	UseAsync           bool   `json:"useAsync" jsonschema:"title=Use async extraction,description=If true then async extraction optimization is enabled. (Default: false),default=false"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	homeDir, _ := os.UserHomeDir()
	p.SecretsDir = filepath.Join(homeDir, ".ghplugin")
	p.UseHTTPs = true
	p.UseAsync = false
}
