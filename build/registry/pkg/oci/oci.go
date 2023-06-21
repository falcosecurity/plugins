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

package oci

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/falcosecurity/plugins/build/registry/pkg/common"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/blang/semver"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/oci/repository"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"k8s.io/klog/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

var (
	bucketName = "falco-distribution"
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

// s3ArtifactName returns the prefix name of the archive uploaded in the s3 bucket.
// It uses the same logic used by the makefile used to upload the artifacts in the s3 bucket.
func s3ArtifactNamePrefix(plugin *registry.Plugin, version string, rulesFile bool) string {
	if rulesFile {
		return fmt.Sprintf("%s-rules-%s%s", plugin.Name, version, archive_suffix)
	}
	return fmt.Sprintf("%s-%s-linux", plugin.Name, version)
}

func platformFromS3Key(key string) string {
	if strings.Contains(key, x86_arch_s3) {
		// Instead of "x86_64" we return "amd64" the one to be used in the oci artifact.
		return fmt.Sprintf("linux/%s", amd64OCI)
	}

	if strings.Contains(key, arm_aarch64_s3) {
		// Instead of "aarch64" we return "arm64" the one to be used in the oci artifact.
		return fmt.Sprintf("linux/%s", arm64OCI)
	}

	// Return empty string if it does not contain one of the expected architectures.
	return ""
}

func currentPlatform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

// latestVersionArtifact returns the latest version of the artifact that exists in the remote repository pointed by the reference.
func latestVersionArtifact(ctx context.Context, ref string, ociClient remote.Client) (string, error) {
	var versions []semver.Version
	var repo *repository.Repository
	var err error

	// Create the repository object for the ref.
	if repo, err = repository.NewRepository(ref, repository.WithClient(ociClient)); err != nil {
		return "", fmt.Errorf("unable to create repository for ref %q: %w", ref, err)
	}

	// Get all the tags for the given artifact in the remote repository.
	remoteTags, err := repo.Tags(ctx)
	// Only way to know if the repo does not exist is to check the content of the error.
	if err != nil && !strings.Contains(err.Error(), "unexpected status code 404") {
		klog.Errorf("unable to get latest version from remote repository for %q: %v", ref, err)
		return "", err
	}

	// If no tags found it means that the artifact does not exist in the OCI registry or
	// that it does not have tags.
	if len(remoteTags) == 0 {
		return "", nil
	}

	// We parse the tags in semVer and then sort and get the latest one.
	for _, tag := range remoteTags {
		// Ignore the "latest" tag.
		if tag == "latest" {
			continue
		}
		parsedVersion, err := semver.ParseTolerant(tag)
		if err != nil {
			return "", fmt.Errorf("cannot parse tag %q to semVer: %v", tag, err)
		}

		versions = append(versions, parsedVersion)
	}

	// Sort the versions.
	semver.Sort(versions)

	// Return the latest version.
	// It should never happen that versions is empty. Since the artifacts are pushed by the CI if
	// it has been pushed then it must have a tag assigned to it.
	return versions[len(versions)-1].String(), nil
}

// TODO(alacuku): duplicated code, in common with the "version" tool
func git(args ...string) (output []string, err error) {
	stdout, err := exec.Command("git", args...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("unable to list tags %q: %v", exitErr.Stderr, err)
		}
		return nil, err
	}

	lines := strings.Split(string(stdout), "\n")

	return lines[0 : len(lines)-1], nil
}

// localLatestVersion returns the latest version of the artifact in the local git repository based on the tags.
func localLatestVersion(artifactName string) (*semver.Version, error) {
	// List only the tags that have a prefix "artifactname-[0-9].*"
	tagPrefix := fmt.Sprintf("%s-[0-9].*", artifactName)
	tags, err := git("--no-pager", "tag", "-l", tagPrefix, "--sort", "-authordate")
	if err != nil {
		return nil, err
	}

	if len(tags) == 0 {
		return nil, fmt.Errorf("no tags found for prefix %q", tagPrefix)
	}

	// Trim tag's prefix.
	tag := strings.TrimPrefix(tags[0], artifactName+"-")
	version, err := semver.Parse(tag)
	if err != nil {
		return nil, fmt.Errorf("unable to parse tag %q to semver: %v", tags[0], err)
	}

	return &version, err
}

// newReleases returns the new released versions since the latest version fetched from the remote repository.
// It could happen that the artifact does not exist in the remote repository, in that case we return the latest
// version found in the local git repository.
func newReleases(artifactName, remoteVersion string) ([]semver.Version, error) {
	var versions []semver.Version

	// List only the tags that have a prefix "artifactname-[0-9].*"
	tagPrefix := fmt.Sprintf("%s-[0-9].*", artifactName)
	remoteTag := fmt.Sprintf("%s-%s", artifactName, remoteVersion)

	// If the artifact does not exist in the OCI repo, then we just get the latest version in the
	// local git repo.
	if remoteVersion == "" {
		v, err := localLatestVersion(artifactName)
		if err != nil {
			return nil, err
		}
		return append(versions, *v), nil
	}

	tags, err := git("--no-pager", "tag", "--list", tagPrefix, "--contains", remoteTag)
	if err != nil {
		return nil, err
	}

	// Since the remoteTag is always self-contained, we remove it.
	tags = tags[1:]

	// If not new versions are found then return.
	if len(tags) == 0 {
		return nil, nil
	}

	for _, tag := range tags {

		if tag == "" {
			continue
		}
		// Trim tag's prefix.
		t := strings.TrimPrefix(tag, artifactName+"-")

		parsedVersion, err := semver.Parse(t)
		if err != nil {
			return nil, fmt.Errorf("cannot parse tag %q to semVer: %v", t, err)
		}

		versions = append(versions, parsedVersion)
	}

	// Sort and return the versions.
	semver.Sort(versions)
	return versions, nil
}

// DoUpdateOCIRegistry publishes new plugins with related rules to be released.
// For each plugin in the registry index, it looks for new versions, since the latest version fetched from the remote OCI
// repository, as tags on the local Git repository.
// For each new version, it downloads the related plugin and rule set from the Falco distribution and updates the OCI
// repository accordingly.
func DoUpdateOCIRegistry(ctx context.Context, registryFile string) ([]registry.ArtifactPushMetadata, error) {
	var (
		cfg *config
		err error
	)

	// Load the configuration from env variables.
	if cfg, err = lookupConfig(); err != nil {
		return nil, err
	}

	s3Client := s3.NewFromConfig(aws.Config{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
	})

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
		pa, ra, err := handleArtifact(ctx, cfg, &plugin, s3Client, ociClient)
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

func listObjects(ctx context.Context, client *s3.Client, prefix string) ([]string, error) {
	prefix = filepath.Join(pluginPrefix, prefix)
	params := &s3.ListObjectsV2Input{
		Bucket: &bucketName,
		Prefix: &prefix,
	}

	klog.Infof("listing objects for plugin from s3 bucket with prefix %q", prefix)

	// Create the Paginator for the ListObjectsV2 operation.
	p := s3.NewListObjectsV2Paginator(client, params, func(o *s3.ListObjectsV2PaginatorOptions) {
		if v := int32(maxKeys); v != 0 {
			o.Limit = v
		}
	})

	var keys []string

	// Iterate through the S3 object pages, printing each object returned.
	var i int
	for p.HasMorePages() {
		i++

		// Next Page takes a new context for each page retrieval. This is where
		// you could add timeouts or deadlines.
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("an error occurred while getting next page from s3 bucket while handling prefix %q: %w", prefix, err)
		}

		// Add keys to the slice.
		for _, obj := range page.Contents {
			keys = append(keys, *obj.Key)
		}
	}

	klog.V(5).Infof("objects found for prefix %q: %s", prefix, keys)
	return keys, nil
}

func downloadToFile(downloader *manager.Downloader, targetDirectory, bucket, key string) error {
	// Create the directories in the path
	file := filepath.Join(targetDirectory, key)
	if err := os.MkdirAll(filepath.Dir(file), 0775); err != nil {
		return err
	}

	// Set up the local file
	fd, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fd.Close()

	// Download the file using the AWS SDK for Go
	_, err = downloader.Download(context.Background(), fd, &s3.GetObjectInput{Bucket: &bucket, Key: &key})

	return err
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

// handleArtifact discovers new plugin and related rules releases to be published comparing the Git local latest version,
// with the remote latest version, on the OCI repository.
// For each new release version, it pushes the plugin and rule set, downloading the content from the official Falco
// distribution.
func handleArtifact(ctx context.Context, cfg *config, plugin *registry.Plugin,
	s3Client *s3.Client, ociClient remote.Client) ([]registry.ArtifactPushMetadata, []registry.ArtifactPushMetadata, error) {
	// Filter out plugins that are not owned by falcosecurity.
	if plugin.Authors != falcoAuthors {
		sepString := strings.Repeat("#", 15)
		klog.Infof("%s %s %s", sepString, plugin.Name, sepString)
		klog.Infof("skipping plugin %q with authors %q: it is not maintained by %q",
			plugin.Name, plugin.Authors, falcoAuthors)
		return nil, nil, nil
	}

	// Handle the plugin.
	newPluginArtifacts, err := handlePlugin(ctx, cfg, plugin, s3Client, ociClient)
	if err != nil {
		return nil, nil, err
	}

	// Handle the rules.
	newRuleArtifacts := []registry.ArtifactPushMetadata{}

	if plugin.RulesURL != "" {
		newRuleArtifacts, err = handleRule(ctx, cfg, plugin, s3Client, ociClient)
		if err != nil {
			return nil, nil, err
		}
	}

	return newPluginArtifacts, newRuleArtifacts, nil
}

// handlePlugin discovers new releases to be published comparing the local latest version, as a git tag on the local
// repository, with the remote latest version, as latest published tag on the remote OCI repository.
// For each new release version, it pushes the plugin with as tag the new release version, and as content the one
// downloaded from the official Falco distribution.
func handlePlugin(ctx context.Context, cfg *config, plugin *registry.Plugin,
	s3Client *s3.Client, ociClient remote.Client) ([]registry.ArtifactPushMetadata, error) {
	var s3Keys []string
	var configLayer *oci.ArtifactConfig
	var err error

	sepString := strings.Repeat("#", 15)
	klog.Infof("%s %s %s", sepString, plugin.Name, sepString)

	ref := refFromPluginEntry(cfg, plugin, false)
	// Get all the tags for the given artifact in the remote repository.
	remoteVersion, err := latestVersionArtifact(ctx, ref, ociClient)
	if err != nil {
		return nil, err
	}

	if remoteVersion != "" {
		klog.Infof("latest version found in the OCI registry is: %q", remoteVersion)
	} else {
		klog.Info("no versions found in the OCI registry")
	}

	// New releases to be published.
	releases, err := newReleases(plugin.Name, remoteVersion)
	if err != nil {
		return nil, err
	}

	// If there are no new releases then return.
	if len(releases) == 0 {
		klog.Info("no new releases found in the local git repo. Nothing to be done")
		return nil, nil
	} else {
		klog.Infof("new releases found in local git repo: %q", releases)
	}

	// Create s3 downloader.
	downloader := manager.NewDownloader(s3Client)

	// Metadata of the plugins OCI artifacts push.
	metadata := []registry.ArtifactPushMetadata{}

	// For each new release we download the tarballs from s3 bucket.
	for _, v := range releases {
		prefixKey := s3ArtifactNamePrefix(plugin, v.String(), false)
		// Get the s3 keys.
		if s3Keys, err = listObjects(ctx, s3Client, prefixKey); err != nil {
			return nil, fmt.Errorf("an error occurred while listing objects for prefix %q: %v", prefixKey, err)
		}

		// It could happen if we tagged a new version in the git repo but the CI has not processed it.
		// It means that no binaries have been produced and uploaded in the s3 bucket.
		if len(s3Keys) == 0 {
			klog.Warningf("no archives found on s3 bucket for prefix %q", prefixKey)
			continue
		}

		var filepaths, platforms []string

		// Download the tarballs for each key.
		for _, key := range s3Keys {
			klog.Infof("downloading tarball with key %q", key)
			if err := downloadToFile(downloader, plugin.Name, bucketName, key); err != nil {
				return nil, fmt.Errorf("an error occurred while downloading tarball %q from bucket %q: %w",
					key, bucketName, err)
			}

			filepaths = append(filepaths, filepath.Join(plugin.Name, key))
			platforms = append(platforms, platformFromS3Key(key))
		}

		tags := tagsFromVersion(&v)

		klog.Infof("generating plugin's config layer")

		// current platform where the CI is running.
		platform := currentPlatform()
		for i, p := range platforms {
			// We need to get the plugin that have been built for the same platform as the one where we are loading it.
			if p == platform {
				configLayer, err = pluginConfig(plugin.Name, v.String(), filepaths[i])
				if err != nil {
					klog.Errorf("unable to generate config file: %v", err)
					return nil, err
				}
				break
			}
			continue
		}

		if configLayer == nil {
			klog.Warningf("no config layer generated for plugin %q: the plugins has not been build for the current platform %q", plugin.Name, platform)
			return nil, nil
		}

		klog.Infof("pushing plugin to remote repo with ref %q and tags %q", ref, tags)
		pusher := ocipusher.NewPusher(ociClient, false, nil)
		res, err := pusher.Push(context.Background(), oci.Plugin, ref,
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
	}

	return metadata, nil
}

// handleRule discovers new releases to be published comparing the local latest version, as a git tag on the local
// repository, with the remote latest version, as latest published tag on the remote OCI repository.
// For each new release version, it pushes the rule set with as tag the new release version, and as content the one
// downloaded from the official Falco distribution.
func handleRule(ctx context.Context, cfg *config, plugin *registry.Plugin,
	s3Client *s3.Client, ociClient remote.Client) ([]registry.ArtifactPushMetadata, error) {
	var s3Keys []string
	var err error

	sepString := strings.Repeat("#", 15)
	klog.Infof("%s %s %s", sepString, rulesfileNameFromPlugin(plugin.Name), sepString)

	ref := refFromPluginEntry(cfg, plugin, true)
	// Get all the tags for the given artifact in the remote repository.
	remoteVersion, err := latestVersionArtifact(ctx, ref, ociClient)
	if err != nil {
		return nil, err
	}

	if remoteVersion != "" {
		klog.Infof("latest version found in the OCI registry is: %q", remoteVersion)
	} else {
		klog.Info("no versions found in the OCI registry")
	}

	// New releases to be published.
	releases, err := newReleases(plugin.Name, remoteVersion)
	if err != nil {
		return nil, err
	}

	// If there are no new releases then return.
	if len(releases) == 0 {
		klog.Info("no new releases found in the local git repo. Nothing to be done")
		return nil, nil
	} else {
		klog.Infof("new releases found in local git repo: %q", releases)
	}

	// Create s3 downloader.
	downloader := manager.NewDownloader(s3Client)

	// Metadata of the rules OCI artifacts push.
	metadata := []registry.ArtifactPushMetadata{}

	// For each new version we download the archives from s3 bucket
	for _, v := range releases {
		prefixKey := s3ArtifactNamePrefix(plugin, v.String(), true)
		// Get the s3 keys.
		if s3Keys, err = listObjects(ctx, s3Client, prefixKey); err != nil {
			return nil, fmt.Errorf("an error occurred while listing objects for prefix %q: %v", prefixKey, err)
		}

		// It could happen if we tagged a new version in the git repo but the CI has not processed it.
		// It means that no binaries have been produced and uploaded in the s3 bucket.
		if len(s3Keys) == 0 {
			klog.Warningf("no archives found on s3 bucket for prefix %q", prefixKey)
			continue
		}

		// For a given release of a rulesfile there should be only one archive in the s3 bucket.
		if len(s3Keys) > 1 {
			err := fmt.Errorf("multiple archives found for rulesfiles with prefix %q: %s", prefixKey, s3Keys)
			klog.Error(err)
			return nil, err
		}

		var filepaths []string

		key := s3Keys[0]
		klog.Infof("downloading tarball with key %q", key)
		if err := downloadToFile(downloader, plugin.Name, bucketName, key); err != nil {
			return nil, fmt.Errorf("an error occurred while downloading tarball %q from bucket %q: %w",
				key, bucketName, err)
		}
		filepaths = append(filepaths, filepath.Join(plugin.Name, key))

		tags := tagsFromVersion(&v)

		klog.Infof("generating rulesfile's config layer")

		configLayer, err := rulesfileConfig(rulesfileNameFromPlugin(plugin.Name), v.String(), filepaths[0])
		if err != nil {
			klog.Errorf("unable to generate config file: %v", err)
			return nil, err
		}
		klog.Infof("pushing rulesfile to remote repo with ref %q and tags %q", ref, tags)
		pusher := ocipusher.NewPusher(ociClient, false, nil)
		res, err := pusher.Push(context.Background(), oci.Rulesfile, ref,
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
	}

	return metadata, nil
}

func rulesfileNameFromPlugin(name string) string {
	return fmt.Sprintf("%s%s", name, common.RulesArtifactSuffix)
}
