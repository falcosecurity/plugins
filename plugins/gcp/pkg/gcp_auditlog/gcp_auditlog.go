package gcp_auditlog

import (

	// "io/ioutil"
	// "fmt"
	// "github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"context"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 999
	PluginName               = "gcp_auditlog"
	PluginDescription        = "Reference plugin for educational purposes"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.6.0"
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

// func (p *Plugin) Open(topic string) (source.Instance, error) {

// 	pull := func(ctx context.Context, evt sdk.EventWriter) error {

// 		contents, err := ioutil.ReadFile(p.Config.AuditLogsFilePath)

// 		if err != nil {
// 			fmt.Errorf("Error when opening file: ", err)
// 		}

// 		// Write the event data
// 		n, err := evt.Writer().Write(contents)

// 		if err != nil {
// 			return err
// 		} else if n < len(contents) {
// 			return fmt.Errorf("auditlogs message too long: %d, but %d were written", len(contents), n)
// 		}

// 		return err
// 	}
// 	return source.NewPullInstance(pull)
// }
