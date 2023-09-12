package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/gcpaudit/pkg/gcpaudit"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &gcpaudit.Plugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

func main() {}
