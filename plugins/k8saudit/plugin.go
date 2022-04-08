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

package main

import (
	"encoding/json"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
)

type K8SAuditPluginConfig struct {
	SSLCertificate string `json:"sslCertificate" jsonschema:"description=The SSL Certificate to be used with the HTTPS Webhook endpoint (Default: /etc/falco/falco.pem)"`
	MaxEventBytes  uint64 `json:"maxEventBytes"  jsonschema:"description=Max size in bytes for an event JSON payload (Default: 1048576)"`
}

type K8SAuditPlugin struct {
	plugins.BasePlugin
	config    K8SAuditPluginConfig
	extractor k8saudit.AuditEventExtractor
}

func (k *K8SAuditPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          1,
		Name:        "k8saudit",
		Description: "Read Kubernetes Audit Events and monitor Kubernetes Clusters",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.1.0",
		EventSource: "k8s_audit",
	}
}

func (k *K8SAuditPluginConfig) reset() {
	k.MaxEventBytes = 1048576
	k.SSLCertificate = "/etc/falco/falco.pem"
}

func (k *K8SAuditPlugin) Init(cfg string) error {
	k.config.reset()
	return json.Unmarshal([]byte(cfg), &k.config)
}

func (p *K8SAuditPlugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		// all properties are optional by default
		RequiredFromJSONSchemaTags: true,
		// unrecognized properties don't cause a parsing failures
		AllowAdditionalProperties: true,
	}
	if schema, err := reflector.Reflect(&K8SAuditPlugin{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func init() {
	p := &K8SAuditPlugin{}
	source.Register(p)
	extractor.Register(p)
}

func main() {}
