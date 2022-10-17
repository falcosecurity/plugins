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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"k8s.io/klog/v2"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/blang/semver"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	reg "github.com/falcosecurity/plugins/build/registry/pkg/registry"

	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	region        = "eu-west-1" // TODO: make it discoverable
	bucketName    = "falco-distribution"
	pluginPrefix  = "plugins/stable/"
	maxKeys       = 128
	versionRegexp = regexp.MustCompile(`([0-9]+(\.[0-9]+){2})(-rc[0-9]+)?`)
	falcoAuthors  = "The Falco Authors"
)

// Check the
func doUpdateOCIRegistry(registryFile string) error {
	var registry, repoGit, user, token string
	var found bool
	klog.InitFlags(nil)
	flag.Parse()

	ctx := context.Background()

	if token, found = os.LookupEnv(reg.RegistryToken); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", reg.RegistryToken)
	}

	if user, found = os.LookupEnv(reg.RegistryUser); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", reg.RegistryUser)
	}

	if registry, found = os.LookupEnv(reg.RegistryOCI); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", reg.RegistryOCI)
	}

	if repoGit, found = os.LookupEnv(reg.RepoGithub); !found {
		return fmt.Errorf("environment variable with key %q not found, please set it before running this tool", reg.RepoGithub)
	}

	cfg := aws.Config{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
	}

	s3Client := s3.NewFromConfig(cfg)
	ociClient := OCIClient(user, token)

	reg, err := loadRegistryFromFile(registryFile)
	if err != nil {
		return fmt.Errorf("an error occurred while loading registry entries from file %q: %v", registryFile, err)
	}

	sepString := strings.Repeat("#", 15)
	for _, plugin := range reg.Plugins {
		// Filter out plugins that are not owned by falcosecurity
		if plugin.Authors != falcoAuthors {
			klog.V(4).Infof("skipping plugin %q with authors %q: it is not maintained by %q",
				plugin.Name, plugin.Authors, falcoAuthors)
			continue
		}

		klog.Infof("%s %s %s", sepString, plugin.Name, sepString)

		keys, err := listObjects(ctx, s3Client, plugin.Name)
		if err != nil {
			return fmt.Errorf("unable to list objects from s3 bucket: %v", err)
		}

		if err = handlePlugins(ctx, s3Client, ociClient, registry, registryFile, user, repoGit, plugin.Name, keys); err != nil {
			return fmt.Errorf("error handle plugins: %w", err)
		}

		if err = handleRules(ctx, s3Client, ociClient, registry, registryFile, user, repoGit, plugin.Name, keys); err != nil {
			return fmt.Errorf("error handle rules: %w", err)
		}

		// Remove the folders and files downloaded from s3 bucket.
		if err := os.RemoveAll(plugin.Name); err != nil {
			return fmt.Errorf("unable to remove folder %q: %v", plugin.Name, err)
		}
	}

	return nil
}

func listObjects(ctx context.Context, client *s3.Client, name string) ([]string, error) {
	prefix := filepath.Join(pluginPrefix, name)
	params := &s3.ListObjectsV2Input{
		Bucket: &bucketName,
		Prefix: &prefix,
	}

	klog.Infof("listing objects for plugin %q from s3 bucket with prefix %q", name, prefix)

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
			return nil, fmt.Errorf("an error occurred while getting next page from s3 bucket while handling plugin %q: %w", name, err)
		}

		// Add keys to the slice.
		for _, obj := range page.Contents {
			keys = append(keys, *obj.Key)
		}
	}

	klog.V(5).Infof("objects found for plugin %q: %s", name, keys)
	return keys, nil
}

func handlePlugins(ctx context.Context, s3client *s3.Client, ociClient *auth.Client, registry, registryFile, registryUser, repoGit, pluginName string, keys []string) error {
	klog.Infof("Handling plugin %q...", pluginName)
	pluginVersions := make(map[string][]string)
	var allPluginVersions []string
	for _, key := range keys {
		if strings.Contains(key, "rules") {
			continue
		}

		version, err := version(key)
		if err != nil {
			return fmt.Errorf("an error occurred while getting version from plugin %q: %w", pluginName, err)
		}
		pluginVersions[version] = append(pluginVersions[version], key)
		allPluginVersions = append(allPluginVersions, version)
	}

	klog.Infof("plugin versions found in the s3 bucket: %s", allPluginVersions)

	// there exists plugins that are not stored in s3 yet (e.g "k8saudit-eks")
	if len(allPluginVersions) == 0 {
		klog.Warningf("plugin %q found in %q but not in the s3 bucket: nothing to be done", pluginName, registryFile)
		return nil
	}

	latest, err := latestVersion(allPluginVersions)
	if err != nil {
		return fmt.Errorf("a error occurred while getting latest version for plugin %q: %w", pluginName, err)
	}

	klog.Infof("latest version found in s3 bucket for plugin %q: %q", pluginName, latest)

	ref := filepath.Join(registry, registryUser, reg.PluginNamespace, pluginName)
	registryTags, err := oci.Tags(ctx, ref, ociClient)
	klog.Infof("plugin versions found in the OCI registry: %s", registryTags)
	// TODO: better handling errors.
	if err == nil {
		for _, tag := range registryTags {
			// check that all platform on s3 are also in oci
			taggedRef := ref + ":" + tag
			ociPlatforms, err := oci.Platforms(context.Background(), taggedRef, ociClient)
			if err != nil {
				return err
			}

			s3Platforms, ok := pluginVersions[tag]
			if !ok && tag != "latest" {
				return fmt.Errorf("fatal error: expected to find %q in pluginVersions", tag)
			}

			if len(ociPlatforms) == len(s3Platforms) {
				klog.V(4).Infof("skipping version %q for plugin %q: found in both oci registry and s3 bucket", tag, pluginName)
				delete(pluginVersions, tag)
			}
		}
	}

	// add :latest logic
	for tag, s3key := range pluginVersions {
		var filepaths, platforms, tags []string
		downloader := manager.NewDownloader(s3client)
		for _, pluginKey := range s3key {
			klog.Infof("downloading plugin with key %q", pluginKey)
			if err := downloadToFile(downloader, pluginName, bucketName, pluginKey); err != nil {
				return fmt.Errorf("an error occurred while downloading plugin %q from bucket %q with key %q: %w",
					pluginName, bucketName, pluginKey, err)
			}
			filepaths = append(filepaths, filepath.Join(pluginName, pluginKey))
			version, err := version(pluginKey)
			if err != nil {
				return fmt.Errorf("an error occurred while getting version from plugin %q: %w", pluginName, err)
			}
			platforms = append(platforms, platform(pluginKey, version))
		}

		// push
		tags = append(tags, tag)
		if tag == latest {
			tags = append(tags, "latest")
		}
		klog.Infof("pushing plugin to remote repo with ref %q and tags %q", ref, tags)
		pusher := ocipusher.NewPusher(ociClient, false, nil)
		_, err := pusher.Push(context.Background(), oci.Plugin, ref+":"+tag,
			ocipusher.WithTags(tags...),
			ocipusher.WithFilepathsAndPlatforms(filepaths, platforms),
			ocipusher.WithAnnotationSource(repoGit))
		if err != nil {
			return fmt.Errorf("an error occurred while pushing plugin %q: %w", pluginName, err)
		}
	}

	if len(pluginVersions) == 0 {
		klog.Infof("nothing to be done for plugin %q, already present in the OCI registry", pluginName)
	}
	return nil
}

func handleRules(ctx context.Context, s3Client *s3.Client, ociClient *auth.Client, registry, registryFile, registryUser, repoGit, rulesetName string, keys []string) error {
	klog.Infof("Handling ruleset %q...", rulesetName)
	ruleVersions := make(map[string]string)
	var allRuleVersions []string
	for _, key := range keys {
		if !strings.Contains(key, "rules") {
			continue
		}

		version, err := version(key)
		if err != nil {
			return fmt.Errorf("an error occurred while getting version from ruleset %q: %w", rulesetName, err)
		}
		ruleVersions[version] = key
		allRuleVersions = append(allRuleVersions, version)
	}

	// there exists plugin that do not have rules
	if len(allRuleVersions) == 0 {
		klog.Warningf("ruleset %q found in %q but not in the s3 bucket: nothing to be done", rulesetName, registryFile)
		return nil
	}

	klog.Infof("ruleset versions found in the s3 bucket: %s", allRuleVersions)

	latest, err := latestVersion(allRuleVersions)
	if err != nil {
		return fmt.Errorf("a error occurred while getting latest version for ruleset %q: %w", rulesetName, err)
	}

	klog.Infof("latest version found in s3 bucket for ruleset %q: %q", rulesetName, latest)

	ref := filepath.Join(registry, registryUser, reg.RulesfileNamespace, rulesetName)
	registryTags, err := oci.Tags(ctx, ref, ociClient)
	klog.Infof("ruleset versions found in the OCI registry: %s", registryTags)
	if err == nil {
		for _, tag := range registryTags {
			klog.V(4).Infof("skipping version %q for ruleset %q: found in both oci registry and s3 bucket", tag, rulesetName)
			delete(ruleVersions, tag)
		}
	}

	for tag, s3key := range ruleVersions {
		var filepaths, tags []string
		downloader := manager.NewDownloader(s3Client)

		klog.Infof("downloading ruleset with key %q", s3key)
		if err := downloadToFile(downloader, rulesetName, bucketName, s3key); err != nil {
			return fmt.Errorf("an error occurred while downloading ruleset %q from bucket %q with key %q: %w",
				rulesetName, bucketName, s3key, err)
		}
		filepaths = append(filepaths, filepath.Join(rulesetName, s3key))

		// push
		tags = append(tags, tag)
		if tag == latest {
			tags = append(tags, "latest")
		}
		klog.Infof("pushing ruleset to remote repo with ref %q and tags %q", ref, tags)
		pusher := ocipusher.NewPusher(ociClient, false, nil)
		_, err := pusher.Push(context.Background(), oci.Rulesfile, ref+":"+tag,
			ocipusher.WithTags(tags...),
			ocipusher.WithFilepaths(filepaths),
			ocipusher.WithAnnotationSource(repoGit))
		if err != nil {
			return fmt.Errorf("an error occurred while pushing ruleset %q: %w", rulesetName, err)
		}
	}

	if len(ruleVersions) == 0 {
		klog.Infof("nothing to be done for ruleset %q, already present in the OCI registry", rulesetName)
	}

	return nil
}

func latestVersion(versions []string) (string, error) {
	if len(versions) == 0 {
		return "", fmt.Errorf("cannot get latest version from empty array")
	}
	var parsedVersions []semver.Version
	for _, v := range versions {
		// skip rc version since they cannot be "latest"
		if strings.Contains(v, "rc") {
			continue
		}
		parsedVersion, err := semver.Parse(v)
		if err != nil {
			return "", fmt.Errorf("cannot parse version %q", v)
		}
		parsedVersions = append(parsedVersions, parsedVersion)
	}

	semver.Sort(parsedVersions)
	return parsedVersions[len(parsedVersions)-1].String(), nil
}

func OCIClient(username, token string) *auth.Client {
	cred := auth.Credential{
		Username: username,
		Password: token,
	}

	return authn.NewClient(cred)
}

func version(key string) (string, error) {
	matches := versionRegexp.FindStringSubmatch(key)
	if len(matches) == 0 {
		return "", fmt.Errorf("regexp %q not match found in string %q while extracting the version", versionRegexp.String(), key)
	}
	return matches[0], nil
}

func platform(key, version string) string {
	oldKey := key
	index := strings.Index(key, version)
	key = key[index+len(version)+1:]
	key = strings.TrimSuffix(key, ".tar.gz")
	key = strings.Replace(key, "-", "/", 1)

	if !strings.Contains(key, "linux") {
		key = "linux/" + key
	}

	key = strings.Replace(key, "x86_64", "amd64", 1)

	klog.V(4).Infof("platform %q extracted from key %q", key, oldKey)
	return key
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
