package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/kafka/pkg/kafka"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &kafka.Plugin{}
		source.Register(p)
		return p
	})
}

func main() {}
