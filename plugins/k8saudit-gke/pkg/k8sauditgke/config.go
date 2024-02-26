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
	"log"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
	"github.com/patrickmn/go-cache"
	"google.golang.org/api/container/v1"
)

type Plugin struct {
	k8saudit.Plugin
	logger *log.Logger
	Config PluginConfig

	containerService *container.Service
	metadataCache    *cache.Cache
}

type PluginConfig struct {
	ProjectID              string `json:"project_id"               jsonschema:"title=Project ID,description=A unique identifier for a GCP project (Default: empty),default="`
	CredentialsFile        string `json:"credentials_file"         jsonschema:"title=Credentials File,description=If non-empty overrides the default GCP credentials file (e.g. ~/.config/gcloud/application_default_credentials.json) and env variables such as GOOGLE_APPLICATION_CREDENTIALS (Default: empty),default="`
	NumGoroutines          int    `json:"num_goroutines"           jsonschema:"title=Num Goroutines,description=The number of goroutines that each datastructure along the PubSub Receive path will spawn (Default: 10),default=10"`
	MaxOutstandingMessages int    `json:"max_outstanding_messages" jsonschema:"title=Max Outstanding Messages,description=The maximum number of unprocessed PubSub messages (Default: 1000),default=1000"`
	FetchClusterMetadata   bool   `json:"fetch_cluster_metadata"   jsonschema:"title=Fetch cluster metadata labels,description=(Default: false),default=false"`
	CacheExpiration        uint64 `json:"cache_expiration"         jsonschema:"title=Cluster metadata cache expiration (in minutes),description=(Default: 10),default=10"`
	UseAsync               bool   `json:"use_async"                jsonschema:"title=Use async extraction,description=If true then async extraction optimization is enabled (Default: true),default=true"`
	MaxEventSize           uint64 `json:"max_event_size"           jsonschema:"title=Maximum event size,description=Maximum size of single audit event (Default: 262144),default=262144"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	p.ProjectID = ""
	p.CredentialsFile = ""
	p.NumGoroutines = 10
	p.MaxOutstandingMessages = 1000
	p.FetchClusterMetadata = false
	p.CacheExpiration = 10
	p.UseAsync = true
	p.MaxEventSize = uint64(sdk.DefaultEvtSize)
}
