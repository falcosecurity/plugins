// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
	PluginVersion            = "0.2.0"
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
