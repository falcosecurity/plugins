/*
Copyright (C) 2022 The Falco Authors.

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

package distribution

import (
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
)

// Define our conventions.
const (
	GHOrg               = "falcosecurity"
	GHRepo              = "plugins"
	GHRepoFull          = "https://github.com/" + GHOrg + "/" + GHRepo + "/"
	OCIRepoBashPath     = GHOrg + "/" + GHRepo + "/"
	OCIRegistry         = "ghcr.io"
	RulesArtifactSuffix = "-rules"
)

func pluginToIndexEntry(p registry.Plugin) *index.Entry {
	return &index.Entry{
		Name:        p.Name,
		Type:        string(oci.Plugin),
		Registry:    OCIRegistry,
		Repository:  OCIRepoBashPath + p.Name,
		Description: p.Description,
		Home:        p.URL,
		Keywords:    p.Keywords,
		License:     p.License,
		Maintainers: p.Maintainers,
		Sources:     []string{p.URL},
	}
}

func pluginRulesToIndexEntry(p registry.Plugin) *index.Entry {
	return &index.Entry{
		Name:        p.Name + RulesArtifactSuffix,
		Type:        string(oci.Rulesfile),
		Registry:    OCIRegistry,
		Repository:  OCIRepoBashPath + p.Name + RulesArtifactSuffix,
		Description: p.Description,
		Home:        p.URL,
		Keywords:    append(p.Keywords, p.Name+RulesArtifactSuffix),
		License:     p.License,
		Maintainers: p.Maintainers,
		Sources:     []string{p.RulesURL},
	}
}

func UpsertIndex(r *registry.Registry, indexPath string) error {
	i := index.New(GHOrg)

	if err := i.Read(indexPath); err != nil {
		return err
	}

	for _, p := range r.Plugins {
		// We only publish falcosecurity artifacts
		if !p.Reserved && strings.HasPrefix(p.URL, GHRepoFull) {
			i.Upsert(pluginToIndexEntry(p))
			if len(p.RulesURL) > 0 {
				i.Upsert(pluginRulesToIndexEntry(p))
			}
		}
	}

	return i.Write(indexPath)
}
