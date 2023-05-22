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
	"context"
	"errors"
	"fmt"
	"github.com/falcosecurity/plugins/build/registry/pkg/common"
	"os"
	"path/filepath"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/index"
	falcoctloci "github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/plugins/build/registry/pkg/oci"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Define our conventions.
const (
	GHOrg = "falcosecurity"
)

func pluginToIndexEntry(p registry.Plugin, registry, repo string) *index.Entry {
	return &index.Entry{
		Name:        p.Name,
		Type:        string(falcoctloci.Plugin),
		Registry:    registry,
		Repository:  repo,
		Description: p.Description,
		Home:        p.URL,
		Keywords:    appendIfNotPresent(p.Keywords, p.Name),
		License:     p.License,
		Maintainers: p.Maintainers,
		Sources:     []string{p.URL},
	}
}

func pluginRulesToIndexEntry(p registry.Plugin, registry, repo string) *index.Entry {
	return &index.Entry{
		Name:        p.Name + common.RulesArtifactSuffix,
		Type:        string(falcoctloci.Rulesfile),
		Registry:    registry,
		Repository:  repo,
		Description: p.Description,
		Home:        p.URL,
		Keywords:    appendIfNotPresent(p.Keywords, p.Name+common.RulesArtifactSuffix),
		License:     p.License,
		Maintainers: p.Maintainers,
		Sources:     []string{p.RulesURL},
	}
}

func upsertIndex(r *registry.Registry, ociArtifacts map[string]string, indexPath string) error {
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
		if refPlugin, ok := ociArtifacts[p.Name]; ok {
			tokens := strings.Split(refPlugin, "/")
			ociRegistry := tokens[0]
			ociRepo := filepath.Join(tokens[1:]...)
			i.Upsert(pluginToIndexEntry(p, ociRegistry, ociRepo))
		}
		if refRulesfile, ok := ociArtifacts[p.Name+common.RulesArtifactSuffix]; ok {
			tokens := strings.Split(refRulesfile, "/")
			ociRegistry := tokens[0]
			ociRepo := filepath.Join(tokens[1:]...)
			i.Upsert(pluginRulesToIndexEntry(p, ociRegistry, ociRepo))
		}
	}

	return i.Write(indexPath)
}

func DoUpdateIndex(registryFile, indexFile string) error {
	var user, reg string
	var found bool
	if user, found = os.LookupEnv(oci.RegistryUser); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", oci.RegistryUser)
	}

	if reg, found = os.LookupEnv(oci.RegistryOCI); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", oci.RegistryOCI)
	}

	registryEntries, err := registry.LoadRegistryFromFile(registryFile)
	if err != nil {
		return err
	}
	ociEntries, err := ociRepos(registryEntries, reg, user)
	if err != nil {
		return err
	}
	if err := registryEntries.Validate(); err != nil {
		return err
	}

	return upsertIndex(registryEntries, ociEntries, indexFile)
}

func ociRepos(registryEntries *registry.Registry, reg, user string) (map[string]string, error) {
	ociClient := authn.NewClient(authn.WithCredentials(&auth.EmptyCredential))
	ociEntries := make(map[string]string)

	for _, entry := range registryEntries.Plugins {
		if err := ociRepo(ociEntries, ociClient, oci.PluginNamespace, reg, user, entry.Name); err != nil {
			return nil, err
		}

		if entry.RulesURL != "" {
			if err := ociRepo(ociEntries, ociClient, oci.RulesfileNamespace, reg, user, entry.Name); err != nil {
				return nil, err
			}
		}
	}

	return ociEntries, nil
}

func ociRepo(ociEntries map[string]string, client remote.Client, ociRepoNamespace, reg, user, artifactName string) error {
	ref := filepath.Join(reg, user, ociRepoNamespace, artifactName)

	if ociRepoNamespace == oci.RulesfileNamespace {
		artifactName = artifactName + common.RulesArtifactSuffix
	}

	repo, err := remote.NewRepository(ref)
	if err != nil {
		return fmt.Errorf("unable to create repo for ref %q: %w", ref, err)
	}
	repo.Client = client

	_, _, err = repo.FetchReference(context.Background(), ref+":latest")
	if err != nil && (errors.Is(err, errdef.ErrNotFound) || strings.Contains(err.Error(), "requested access to the resource is denied")) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("unable to fetch reference for %q: %w", ref+":latest", err)
	}

	ociEntries[artifactName] = ref
	return nil
}

// Add new item to a slice if not present.
func appendIfNotPresent(keywords []string, kw string) []string {
	// If the keyword already exist do nothing.
	for i := range keywords {
		if keywords[i] == kw {
			return keywords
		}
	}

	// Add the keyword
	return append(keywords, kw)
}
