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

package k8saudit

import (
	"encoding/json"
	"log"
	"os"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/valyala/fastjson"
)

const pluginName = "k8saudit"

// Plugin implements extractor.Plugin and extracts K8S Audit fields from
// K8S Audit events. The event data is expected to be a JSON that in the form
// that is provided by K8S Audit webhook (see https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#webhook-backend).
// The ExtractFromEvent method can be used to easily process an ExtractRequest.
// If the Audit Event data is nested inside another JSON object, you can use
// a combination of the Decode/DecodeEvent and ExtractFromJSON convenience
// methods. Plugin relies on the fastjson package for performant manipulation
// of JSON data.
type Plugin struct {
	plugins.BasePlugin
	logger      *log.Logger
	Config      PluginConfig
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64
}

func (k *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          1,
		Name:        pluginName,
		Description: "Read Kubernetes Audit Events and monitor Kubernetes Clusters",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.6.0",
		EventSource: "k8s_audit",
	}
}

func (k *Plugin) Init(cfg string) error {
	// read configuration
	k.Config.Reset()
	err := json.Unmarshal([]byte(cfg), &k.Config)
	if err != nil {
		return err
	}

	// setup optional async extraction optimization
	extract.SetAsync(k.Config.UseAsync)

	// setup internal logger
	k.logger = log.New(os.Stderr, "["+pluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	return nil
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		// all properties are optional by default
		RequiredFromJSONSchemaTags: true,
		// unrecognized properties don't cause a parsing failures
		AllowAdditionalProperties: true,
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}
