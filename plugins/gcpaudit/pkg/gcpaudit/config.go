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
	AuditLogsFilePath      string `json:"path" jsonschema:"title=path,description="`
	SubscriptionID         string `json:"sub_id" jsonschema:"title=sub_id,description="`
	MaxOutstandingMessages int    `json:"maxout_stand_messages" jsonschema:"title=maxout_stand_messages,description=is the maximum number of unprocessed messages"`
	NumGoroutines          int    `json:"num_goroutines" jsonschema:"title=num_goroutines,description=is the number of goroutines that each datastructure along the Receive path will spawn"`
	MaxOutstandingBytes    int    `json:"maxout_stand_bytes" jsonschema:"title=sub_id,description="`
	ProjectID              string `json:"project_id" jsonschema:"title=project_id,description="`
}

// Reset sets the configuration to its default values
func (auditlogsPlugin *PluginConfig) Reset() {
	auditlogsPlugin.MaxOutstandingMessages = 1000
	auditlogsPlugin.NumGoroutines = 10
}
