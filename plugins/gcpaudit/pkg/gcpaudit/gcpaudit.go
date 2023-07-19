package gcpaudit

import (

	// "io/ioutil"
	// "fmt"
	// "github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"context"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 12
	PluginName               = "gcpaudit"
	PluginDescription        = "Read GCP Audit Logs"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.1.0"
	PluginEventSource        = "gcp_auditlog"
)

func (auditlogsPlugin *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) Open(topic string) (source.Instance, error) {

	ctx, cancel := context.WithCancel(context.Background())

	eventsC, errC := p.pullMsgsSync(ctx, p.Config.ProjectID, p.Config.SubscriptionID)
	pushEventC := make(chan source.PushEvent)

	go func() {
		defer close(eventsC)
		for {
			select {
			case messages := <-eventsC:
				pushEventC <- source.PushEvent{Data: messages}

			case e := <-errC:
				pushEventC <- source.PushEvent{Err: e}
				return
			}
		}
	}()

	return source.NewPushInstance(pushEventC, source.WithInstanceClose(cancel))

}
