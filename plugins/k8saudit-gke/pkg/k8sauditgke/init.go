// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

package k8sauditgke

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/patrickmn/go-cache"
)

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

// initialize state
func (p *Plugin) Init(cfg string) error {
	p.Config.Reset()

	err := json.Unmarshal([]byte(cfg), &p.Config)
	if err != nil {
		return err
	}

	// setup optional async extraction optimization
	extract.SetAsync(p.Config.UseAsync)

	p.logger = log.New(os.Stderr, "["+PluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)

	if p.Config.FetchClusterMetadata {
		service, err := p.NewContainerService(context.Background())
		if err != nil {
			return fmt.Errorf("failed to create Google Container API client: %v", err)
		}
		p.containerService = service

		expiration := time.Duration(p.Config.CacheExpiration) * time.Minute
		p.metadataCache = cache.New(expiration, expiration+30)
	}

	return nil
}
