// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package oci

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"

	"github.com/falcosecurity/plugins/build/registry/pkg/common"

	"github.com/blang/semver"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"k8s.io/klog/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type config struct {
	// registryToken authentication token for the OCI registry.
	registryToken string
	// registryUser user used to interact with the OCI registry.
	registryUser string
	// registryHost hostname of the OCI registry.
	registryHost string
	// pluginsRepo the Ref of the git repository associated with the OCI artifacts.
	pluginsRepo string
}

func lookupConfig() (*config, error) {
	var found bool
	cfg := &config{}

	if cfg.registryToken, found = os.LookupEnv(RegistryToken); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", RegistryToken)
	}

	if cfg.registryUser, found = os.LookupEnv(RegistryUser); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", RegistryUser)
	}

	if cfg.registryHost, found = os.LookupEnv(RegistryOCI); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", RegistryOCI)
	}

	if cfg.pluginsRepo, found = os.LookupEnv(RepoGithub); !found {
		return nil, fmt.Errorf("environment variable with key %q not found, please set it before running this tool", RepoGithub)
	}

	return cfg, nil
}

// refFromPluginEntry returns an OCI reference for a plugin entry in the registry.yaml file.
func refFromPluginEntry(cfg *config, plugin *registry.Plugin, rulesFile bool) string {
	var namespace string

	// If the RulesURL field is set then the artifact is a rulesfile, otherwise a plugin.
	if rulesFile {
		namespace = RulesfileNamespace
	} else {
		namespace = PluginNamespace
	}

	// Build and return the artifact reference.
	return filepath.Join(cfg.registryHost, cfg.registryUser, namespace, plugin.Name)
}

func currentPlatform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// DoUpdateOCIRegistry publishes new plugins with related rules to be released.
// For each plugin in the registry index, it looks for new versions, since the latest version fetched from the remote OCI
// repository, as tags on the local Git repository.
// For each new version, it downloads the related plugin and rule set from the Falco distribution and updates the OCI
// repository accordingly.
func DoUpdateOCIRegistry(ctx context.Context, registryFile, pluginsAMD4, pluginsARM64, rulesfiles, devTag string) ([]registry.ArtifactPushMetadata, error) {
	var (
		cfg *config
		err error
	)

	// Load the configuration from env variables.
	if cfg, err = lookupConfig(); err != nil {
		return nil, err
	}

	cred := &auth.Credential{
		Username: cfg.registryUser,
		Password: cfg.registryToken,
	}

	ociClient := authn.NewClient(authn.WithCredentials(cred))

	reg, err := registry.LoadRegistryFromFile(registryFile)
	if err != nil {
		return nil, fmt.Errorf("an error occurred while loading registry entries from file %q: %v", registryFile, err)
	}

	artifacts := []registry.ArtifactPushMetadata{}

	// For each plugin in the registry index, look for new ones to be released, and publish them.
	for _, plugin := range reg.Plugins {
		pa, ra, err := handleArtifact(ctx, cfg, &plugin, ociClient, pluginsAMD4, pluginsARM64, rulesfiles, devTag)
		if err != nil {
			return artifacts, err
		}

		artifacts = append(artifacts, pa...)
		artifacts = append(artifacts, ra...)

		// Clean up
		if err := os.RemoveAll(plugin.Name); err != nil {
			return artifacts, fmt.Errorf("unable to remove folder %q: %v", plugin.Name, err)
		}
	}

	return artifacts, nil
}

func tagsFromVersion(version *semver.Version) []string {
	var tags []string

	// If we are not handling a release candidate then add floating tags.
	if len(version.Pre) == 0 {
		majorVer := fmt.Sprintf("%d", version.Major)
		minorVer := fmt.Sprintf("%d.%d", version.Major, version.Minor)
		fullVer := version.String()

		tags = append(tags, "latest", majorVer, minorVer, fullVer)
	} else {
		tags = append(tags, version.String())
	}

	return tags
}

// handleArtifact it pushes artifacts related to a given plugin in the registry.yaml file.
// It could happen that for a given plugin no artifacts such as builds and rulesets are available.
// Consider the case when we release a single plugin.
func handleArtifact(ctx context.Context, cfg *config, plugin *registry.Plugin, ociClient remote.Client,
	pluginsAMD64, pluginsARM64, rulesfiles, devTag string) ([]registry.ArtifactPushMetadata, []registry.ArtifactPushMetadata, error) {
	// Filter out plugins that are not owned by falcosecurity.
	if plugin.Authors != FalcoAuthors {
		sepString := strings.Repeat("#", 15)
		klog.V(2).Info("%s %s %s", sepString, plugin.Name, sepString)
		klog.V(2).Infof("skipping plugin %q with authors %q: it is not maintained by %q",
			plugin.Name, plugin.Authors, FalcoAuthors)
		return nil, nil, nil
	}

	// Handle the plugin.
	newPluginArtifacts, err := handlePlugin(ctx, cfg, plugin, ociClient, pluginsAMD64, pluginsARM64, devTag)
	if err != nil {
		return nil, nil, err
	}

	// Handle the rules.
	newRuleArtifacts := []registry.ArtifactPushMetadata{}

	if plugin.RulesURL != "" {
		newRuleArtifacts, err = handleRule(ctx, cfg, plugin, ociClient, rulesfiles, devTag)
		if err != nil {
			return nil, nil, err
		}
	}

	return newPluginArtifacts, newRuleArtifacts, nil
}

// handlePlugin for a given plugin it checks if there exists build artifacts in the given folders, and
// if found packs them as an OCI artifact and pushes them to the registry.
func handlePlugin(ctx context.Context, cfg *config, plugin *registry.Plugin, ociClient remote.Client,
	pluginsAMD64, pluginsARM64 string, devTag string) ([]registry.ArtifactPushMetadata, error) {
	var configLayer *oci.ArtifactConfig
	var err error
	var filepaths, platforms, tags []string
	var version string
	var infoP *plugins.Info

	// Build the reference for the artifact.
	ref := refFromPluginEntry(cfg, plugin, false)

	// Metadata of the plugins OCI artifacts push.
	metadata := []registry.ArtifactPushMetadata{}

	// Get the name of the build object for the amd64 architecture.
	amd64Build, err := buildName(plugin.Name, pluginsAMD64, false)
	if err != nil {
		return nil, err
	}

	if amd64Build != "" {
		if infoP, err = pluginInfo(filepath.Join(pluginsAMD64, amd64Build)); err != nil {
			return nil, err
		}

		// Check that the plugin has the same name as the one we got from the registry.yaml.
		// If not, we skip it. It could happen that plugins share the same prefix, example k8saudit, k8saudit-gke.
		if infoP.Name != plugin.Name {
			// buildName func returned a wrong path starting from the plugin name found in registry.yaml.
			klog.Warningf("skipping plugin since there is a mismatch in plugin name (%q) and plugin info name(%q)", plugin.Name, infoP.Name)
			return nil, nil
		}

		filepaths = append(filepaths, filepath.Join(pluginsAMD64, amd64Build))
		platforms = append(platforms, amd64Platform)
	}

	// Get the name of the build object for the arm64 architecture.
	arm64Build, err := buildName(plugin.Name, pluginsARM64, false)
	if err != nil {
		return nil, err
	}

	if arm64Build != "" {
		filepaths = append(filepaths, filepath.Join(pluginsARM64, arm64Build))
		platforms = append(platforms, arm64Platform)
	}

	if arm64Build == "" && amd64Build == "" {
		return nil, nil
	}

	sepString := strings.Repeat("#", 15)
	klog.Infof("%s %s %s", sepString, plugin.Name, sepString)

	// Extract version from build object.
	klog.Infof("generating plugin's config layer")

	version, tags, err = versionAndTags(plugin.Name, filepath.Base(filepaths[0]), devTag)
	if err != nil {
		return nil, err
	}

	if infoP == nil {
		klog.Warningf("no config layer generated for plugin %q: the plugins has not been build for the current platform %q", plugin.Name, currentPlatform())
		return nil, nil
	}

	configLayer, err = pluginConfig(plugin.Name, version, infoP)
	if err != nil {
		klog.Errorf("unable to generate config file: %v", err)
		return nil, err
	}

	klog.Infof("pushing plugin to remote repo with ref %q and tags %q", ref, tags)
	pusher := ocipusher.NewPusher(ociClient, false, nil)
	res, err := pusher.Push(ctx, oci.Plugin, ref,
		ocipusher.WithTags(tags...),
		ocipusher.WithFilepathsAndPlatforms(filepaths, platforms),
		ocipusher.WithArtifactConfig(*configLayer),
		ocipusher.WithAnnotationSource(cfg.pluginsRepo))
	if err != nil {
		return nil, fmt.Errorf("an error occurred while pushing plugin %q: %w", plugin.Name, err)
	}
	if res != nil {
		metadata = append(metadata, registry.ArtifactPushMetadata{
			registry.RepositoryMetadata{
				Ref: ref,
			},
			registry.ArtifactMetadata{
				Digest: res.Digest,
				Tags:   tags,
			},
		})
	}

	return metadata, nil
}

// handleRule for a given plugin it checks if there exists rulesfiles in the given folder, and
// if found packs them as an OCI artifact and pushes it to the registry.
func handleRule(ctx context.Context, cfg *config, plugin *registry.Plugin,
	ociClient remote.Client, rulesfiles, devTag string) ([]registry.ArtifactPushMetadata, error) {
	var err error
	var filepaths, tags []string
	var version string

	// Build the reference for the artifact.
	ref := refFromPluginEntry(cfg, plugin, true)

	// Metadata of the plugins OCI artifacts push.
	metadata := []registry.ArtifactPushMetadata{}

	// Get the name of the build object for the amd64 architecture.
	rulesfileBuild, err := buildName(plugin.Name, rulesfiles, true)
	if err != nil {
		return nil, err
	}

	if rulesfileBuild != "" {
		filepaths = append(filepaths, filepath.Join(rulesfiles, rulesfileBuild))
	} else {
		return nil, nil
	}

	sepString := strings.Repeat("#", 15)
	klog.Infof("%s %s %s", sepString, rulesfileNameFromPlugin(plugin.Name), sepString)

	klog.Infof("generating rulesfile's config layer")

	version, tags, err = versionAndTags(plugin.Name, filepath.Base(filepaths[0]), devTag)
	if err != nil {
		return nil, err
	}

	configLayer, err := rulesfileConfig(rulesfileNameFromPlugin(plugin.Name), version, filepaths[0])
	if err != nil {
		klog.Errorf("unable to generate config file: %v", err)
		return nil, err
	}

	klog.Infof("pushing rulesfile to remote repo with ref %q and tags %q", ref, tags)
	pusher := ocipusher.NewPusher(ociClient, false, nil)
	res, err := pusher.Push(ctx, oci.Rulesfile, ref,
		ocipusher.WithTags(tags...),
		ocipusher.WithFilepaths(filepaths),
		ocipusher.WithArtifactConfig(*configLayer),
		ocipusher.WithAnnotationSource(cfg.pluginsRepo))

	if err != nil {
		return nil, fmt.Errorf("an error occurred while pushing rulesfile %q: %w", plugin.Name, err)
	}
	if res != nil {
		metadata = append(metadata, registry.ArtifactPushMetadata{
			registry.RepositoryMetadata{
				Ref: ref,
			},
			registry.ArtifactMetadata{
				Digest: res.Digest,
				Tags:   tags,
			},
		})
	}

	return metadata, nil
}

func rulesfileNameFromPlugin(name string) string {
	return fmt.Sprintf("%s%s", name, common.RulesArtifactSuffix)
}

// buildName returns the name of the build object for a given object name.
// It searches in the given folder if build artifact exists that has the same
// prefix as the object. If we are searching for a rulesfiles object then, the
// rulefiles variable needs to be set to true.
func buildName(objName, dirPath string, rulesfile bool) (string, error) {
	if dirPath == "" {
		return "", nil
	}
	// Get the entries
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("unable to get build object for %q: %w", objName, err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if rulesfile {
			if strings.HasPrefix(name, objName+"-rules") {
				return name, nil
			}
		} else {
			if strings.HasPrefix(name, objName) && !strings.Contains(name, "rules") {
				return name, nil
			}
		}
	}
	return "", nil
}

func versionAndTags(pluginName, buildName, devTag string) (string, []string, error) {
	var version string
	var tags []string
	var err error

	if strings.Contains(buildName, "-rules") {
		version = strings.TrimPrefix(buildName, pluginName+"-rules-")
		version = strings.TrimSuffix(version, archiveSuffix)
	} else {
		regexPattern := `\b-linux\S*`
		regex := regexp.MustCompile(regexPattern)
		// Replace all substrings starting with "linux" with an empty string
		version = regex.ReplaceAllString(buildName, "")
		version = strings.TrimPrefix(version, pluginName+"-")
	}

	if devTag != "" {
		return version, append(tags, devTag), nil
	}

	// If not a dev version, we expect to but be semver compatible.
	semVer, err := semver.Parse(version)
	if err != nil {
		return "", nil, fmt.Errorf("unable to parse version for %q: %w", buildName, err)
	}
	return version, tagsFromVersion(&semVer), nil
}
