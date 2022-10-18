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
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"path/filepath"
	"strings"
)

// Define our conventions.
const (
	GHOrg               = "falcosecurity"
	RulesArtifactSuffix = "-rules"
)

func pluginToIndexEntry(p registry.Plugin, registry, repo string) *index.Entry {
	return &index.Entry{
		Name:        p.Name,
		Type:        string(oci.Plugin),
		Registry:    registry,
		Repository:  repo,
		Description: p.Description,
		Home:        p.URL,
		Keywords:    p.Keywords,
		License:     p.License,
		Maintainers: p.Maintainers,
		Sources:     []string{p.URL},
	}
}

func pluginRulesToIndexEntry(p registry.Plugin, registry, repo string) *index.Entry {
	return &index.Entry{
		Name:        p.Name + RulesArtifactSuffix,
		Type:        string(oci.Rulesfile),
		Registry:    registry,
		Repository:  repo,
		Description: p.Description,
		Home:        p.URL,
		Keywords:    append(p.Keywords, p.Name+RulesArtifactSuffix),
		License:     p.License,
		Maintainers: p.Maintainers,
		Sources:     []string{p.RulesURL},
	}
}

func UpsertIndex(r *registry.Registry, ociArtifacts map[string]string, indexPath string) error {
	i := index.New(GHOrg)

	if err := i.Read(indexPath); err != nil {
		return err
	}

	for _, p := range r.Plugins {
		// If the plugins is reserved than we just skip it.
		if p.Reserved {
			continue
		}

		// We only publish falcosecurity artifacts that have been uploaded to the repo.
		ref, ociPluginFound := ociArtifacts[p.Name]
		ref, ociRulesFound := ociArtifacts[p.Name+RulesArtifactSuffix]

		// Build registry and repo starting from the reference.
		tokens := strings.Split(ref, "/")
		ociRegistry := tokens[0]
		ociRepo := filepath.Join(tokens[1:]...)
		if ociPluginFound {
			i.Upsert(pluginToIndexEntry(p, ociRegistry, ociRepo))
		}
		if ociRulesFound {
			i.Upsert(pluginRulesToIndexEntry(p, ociRegistry, ociRepo))
		}
	}

	return i.Write(indexPath)
}
