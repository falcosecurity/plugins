package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/k8saudit-ovh/pkg/k8sauditovh"
)

const (
	PluginID          uint32 = 22
	PluginName               = "k8saudit-ovh"
	PluginDescription        = "Read Kubernetes Audit Events for OVHcloud MKS"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.1.0"
	PluginEventSource        = "k8s_audit"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &k8sauditovh.Plugin{}
		p.SetInfo(
			PluginID,
			PluginName,
			PluginDescription,
			PluginContact,
			PluginVersion,
			PluginEventSource,
		)
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
