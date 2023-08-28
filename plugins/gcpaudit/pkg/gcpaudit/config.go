package gcpaudit

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/valyala/fastjson"
)

type Plugin struct {
	plugins.BasePlugin
	Config PluginConfig

	lastEventNum uint64
	jparser      fastjson.Parser
	jdata        *fastjson.Value
	jdataEvtnum  uint64
}

type PluginConfig struct {
	ProjectID              string `json:"project_id" jsonschema:"title=Project ID,description=A unique identifier for a GCP project (Default: empty),default="`
	CredentialsFile        string `json:"credentials_file" jsonschema:"title=Credentials File,description=If non-empty overrides the default GCP credentials file (e.g. ~/.config/gcloud/application_default_credentials.json) and env variables such as GOOGLE_APPLICATION_CREDENTIALS (Default: empty),default="`
	NumGoroutines          int    `json:"num_goroutines" jsonschema:"title=Num Goroutines,description=The number of goroutines that each datastructure along the Receive path will spawn (Default: 10),default=10"`
	MaxOutstandingMessages int    `json:"max_outstanding_messages" jsonschema:"title=Max Outstanding Messages,description=The maximum number of unprocessed messages (Default: 1000),default=1000"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	p.ProjectID = ""
	p.CredentialsFile = ""
	p.NumGoroutines = 10
	p.MaxOutstandingMessages = 1000
}
