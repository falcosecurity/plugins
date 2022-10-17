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

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry/distribution"
	"github.com/spf13/cobra"
	"io/ioutil"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultTableSubTag = "<!-- REGISTRY -->"
)

func loadRegistryFromFile(fname string) (*registry.Registry, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return registry.Load(file)
}

func doCheck(fileName string) error {
	registry, err := loadRegistryFromFile(fileName)
	if err != nil {
		return err
	}
	return registry.Validate()
}

func doTable(registryFile, subFile, subTag string) error {
	r, err := loadRegistryFromFile(registryFile)
	if err != nil {
		return err
	}

	err = r.Validate()
	if err != nil {
		return err
	}

	table, err := FormatMarkdownTable(r)
	if err != nil {
		return err
	}
	if len(subFile) == 0 {
		fmt.Println(table)
	} else {
		if len(subTag) == 0 {
			return fmt.Errorf("subtag flag is required")
		}
		content, err := ioutil.ReadFile(subFile)
		if err != nil {
			return err
		}
		pieces := strings.SplitN(string(content), subTag, 3)
		if len(pieces) != 3 {
			return fmt.Errorf("can't find two instances of subtag in text file: '%s'", subTag)
		}
		contentStr := fmt.Sprintf("%s%s\n%s\n%s%s", pieces[0], subTag, table, subTag, pieces[2])
		if err = ioutil.WriteFile(subFile, []byte(contentStr), 0666); err != nil {
			return err
		}
	}

	return nil
}

func doUpdateIndex(registryFile, indexFile string) error {
	var user, reg string
	var found bool
	if user, found = os.LookupEnv(registry.RegistryUser); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", registry.RegistryUser)
	}

	if reg, found = os.LookupEnv(registry.RegistryOCI); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", registry.RegistryOCI)
	}

	registryEntries, err := loadRegistryFromFile(registryFile)
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

	return distribution.UpsertIndex(registryEntries, ociEntries, indexFile)
}

func ociRepos(registryEntries *registry.Registry, reg, user string) (map[string]string, error) {
	ociClient := authn.NewClient(auth.EmptyCredential)
	ociEntries := make(map[string]string)

	for _, entry := range registryEntries.Plugins {
		if err := ociRepo(ociEntries, ociClient, registry.PluginNamespace, reg, user, entry.Name); err != nil {
			return nil, err
		}

		if entry.RulesURL != "" {
			if err := ociRepo(ociEntries, ociClient, registry.RulesfileNamespace, reg, user, entry.Name); err != nil {
				return nil, err
			}
		}
	}

	return ociEntries, nil
}

func ociRepo(ociEntries map[string]string, client *auth.Client, ociRepoNamespace, reg, user, artifactName string) error {
	ref := filepath.Join(reg, user, ociRepoNamespace, artifactName)

	if ociRepoNamespace == registry.RulesfileNamespace {
		artifactName = artifactName + distribution.RulesArtifactSuffix
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

func main() {
	checkCmd := &cobra.Command{
		Use:                   "check <filename>",
		Short:                 "Verify the correctness of a plugin registry YAML file",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doCheck(args[0])
		},
	}

	var tableSubFileName string
	var tableSubTab string
	tableCmd := &cobra.Command{
		Use:   "table <filename>",
		Short: "Format a plugin registry YAML file in a MarkDown table",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return doTable(args[0], tableSubFileName, tableSubTab)
		},
	}
	tableFlags := tableCmd.Flags()
	tableFlags.StringVar(&tableSubTab, "subtag", defaultTableSubTag, "A tag that delimits the start and the end of the text section to substitute with the generated table.")
	tableFlags.StringVar(&tableSubFileName, "subfile", "", "If specified, the table will be written inside the file at this path, inserting it between the first two instances of the substitution tag.")

	updateIndexCmd := &cobra.Command{
		Use:                   "update-index <registryFilename> <indexFilename>",
		Short:                 "Update an index file for artifacts distribution using registry data",
		Args:                  cobra.ExactArgs(2),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doUpdateIndex(args[0], args[1])
		},
	}

	updateOCIRegistry := &cobra.Command{
		Use:                   "update-oci-registry <registryFilename>",
		Short:                 "Update the oci registry starting from the registry file and s3 bucket",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doUpdateOCIRegistry(args[0])
		},
	}

	rootCmd := &cobra.Command{
		Use:     "registry",
		Version: "0.2.0",
	}
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(tableCmd)
	rootCmd.AddCommand(updateIndexCmd)
	rootCmd.AddCommand(updateOCIRegistry)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
