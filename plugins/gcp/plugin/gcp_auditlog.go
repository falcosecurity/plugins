package main

import (
	"falcoplugin/pkg/gcp_auditlog"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &gcp_auditlog.Plugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

func main() {}
