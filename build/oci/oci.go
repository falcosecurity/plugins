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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/blang/semver"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	region             = "eu-west-1" // TODO: make it discoverable
	bucketName         = "falco-distribution"
	pluginPrefix       = "plugins/stable/"
	maxKeys            = 128
	OCIRegistry        = "ghcr.io/loresuso"
	PluginNamespace    = "plugin"
	RulesfileNamespace = "ruleset"
	versionRegexp      = regexp.MustCompile(`([0-9]+(\.[0-9]+){2})(-rc[0-9]+)?`)
	falcoAuthors       = "The Falco Authors"
)

type PluginVersions struct {
	Name     string
	Versions []string
}

func main() {
	// Load the SDK's configuration from environment and shared config, and
	// create the client with this.
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("failed to load SDK configuration, %v", err)
	}

	cfg.Region = region
	cfg.Credentials = aws.AnonymousCredentials{}

	client := s3.NewFromConfig(cfg)

	reg, err := loadRegistryFromFile("../../registry.yaml")
	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, plugin := range reg.Plugins {
		// Filter out plugins that are not owned by falcosecurity
		if plugin.Authors != falcoAuthors {
			continue
		}

		keys, err := listObjects(&cfg, client, plugin.Name)
		if err != nil {
			log.Println("error listing objects")
			return
		}

		if err = handlePlugins(client, plugin.Name, keys); err != nil {
			log.Printf("error handle plugins: %v\n", err)
			return
		}

		if err = handleRules(client, plugin.Name, keys); err != nil {
			log.Printf("error handle rules: %v\n", err)
			return
		}
	}

}

func listObjects(cfg *aws.Config, client *s3.Client, name string) ([]string, error) {
	prefix := filepath.Join(pluginPrefix, name)
	params := &s3.ListObjectsV2Input{
		Bucket: &bucketName,
		Prefix: &prefix,
	}

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
		page, err := p.NextPage(context.TODO())
		if err != nil {
			log.Fatalf("failed to get page %v, %v", i, err)
		}

		// Log the objects found
		for _, obj := range page.Contents {
			keys = append(keys, *obj.Key)
		}
	}

	return keys, nil
}

func handlePlugins(s3client *s3.Client, pluginName string, keys []string) error {
	pluginVersions := make(map[string][]string)
	var allPluginVersions []string
	for _, key := range keys {
		if strings.Contains(key, "rules") {
			continue
		}

		version := version(key, pluginName)
		pluginVersions[version] = append(pluginVersions[version], key)
		allPluginVersions = append(allPluginVersions, version)
	}

	// there exists plugin that are not stored in s3 yet (e.g "k8saudit-eks")
	if len(allPluginVersions) == 0 {
		return nil
	}

	latest, err := latestVersion(allPluginVersions)
	if err != nil {
		return fmt.Errorf("cannot sort versions: %w, name: %s", err, pluginName)
	}
	fmt.Printf("plugin latest version for %q: %q\n", pluginName, latest)

	client := OCIClient()

	ref := filepath.Join(OCIRegistry, PluginNamespace, pluginName)
	registryTags, err := oci.Tags(context.Background(), ref, client)
	if err == nil {
		for _, tag := range registryTags {
			// check that all platform on s3 are also in oci
			taggedRef := ref + ":" + tag
			ociPlatforms, err := oci.Platforms(context.Background(), taggedRef, client)
			if err != nil {
				return err
			}

			s3Platforms, ok := pluginVersions[tag]
			if !ok && tag != "latest" {
				return fmt.Errorf("fatal error: expected to find %q in pluginVersions", tag)
			}

			if len(ociPlatforms) == len(s3Platforms) {
				delete(pluginVersions, tag)
			}
		}
	}

	// add :latest logic
	for tag, s3key := range pluginVersions {
		var filepaths, platforms, tags []string
		downloader := manager.NewDownloader(s3client)
		for _, pluginKey := range s3key {
			downloadToFile(downloader, pluginName, bucketName, pluginKey)
			filepaths = append(filepaths, filepath.Join(pluginName, pluginKey))
			platforms = append(platforms, platform(pluginKey, pluginName))
		}

		// push
		tags = append(tags, tag)
		if tag == latest {
			tags = append(tags, "latest")
		}
		pusher := ocipusher.NewPusher(client, false, nil)
		_, err := pusher.Push(context.Background(), oci.Plugin, ref+":"+tag,
			ocipusher.WithTags(tags...),
			ocipusher.WithFilepathsAndPlatforms(filepaths, platforms))
		if err != nil {
			return err
		}
	}

	return nil
}

func handleRules(s3client *s3.Client, pluginName string, keys []string) error {
	ruleVersions := make(map[string]string)
	var allRuleVersions, tags []string
	for _, key := range keys {
		if !strings.Contains(key, "rules") {
			continue
		}

		version := version(key, pluginName)
		ruleVersions[version] = key
		allRuleVersions = append(allRuleVersions, version)
	}

	// there exists plugin that do not have rules
	if len(allRuleVersions) == 0 {
		return nil
	}

	latest, err := latestVersion(allRuleVersions)
	if err != nil {
		return fmt.Errorf("(rules) cannot sort versions: %w, name: %q", err, pluginName)
	}

	client := OCIClient()

	ref := filepath.Join(OCIRegistry, RulesfileNamespace, pluginName)
	registryTags, err := oci.Tags(context.Background(), ref, client)
	if err == nil {
		for _, tag := range registryTags {
			delete(ruleVersions, tag)
		}
	}

	fmt.Printf("rule versions: %v\n", ruleVersions)

	for tag, s3key := range ruleVersions {
		var filepaths []string
		downloader := manager.NewDownloader(s3client)
		downloadToFile(downloader, pluginName, bucketName, s3key)
		filepaths = append(filepaths, filepath.Join(pluginName, s3key))

		// push
		tags = append(tags, tag)
		if tag == latest {
			tags = append(tags, "latest")
		}
		pusher := ocipusher.NewPusher(client, false, nil)
		_, err := pusher.Push(context.Background(), oci.Rulesfile, ref+":"+tag,
			ocipusher.WithTags(tags...),
			ocipusher.WithFilepaths(filepaths))
		if err != nil {
			return err
		}
	}

	return nil
}

func latestVersion(versions []string) (string, error) {
	if len(versions) == 0 {
		return "", fmt.Errorf("cannot get latest version from empty array")
	}
	var parsedVersions []semver.Version
	for _, v := range versions {
		parsedVersion, err := semver.Parse(v)
		if err != nil {
			return "", fmt.Errorf("cannot parse version %q", v)
		}
		parsedVersions = append(parsedVersions, parsedVersion)
	}

	semver.Sort(parsedVersions)
	return parsedVersions[len(parsedVersions)-1].String(), nil
}

func OCIClient() *auth.Client {
	token := os.Getenv("GHCR_TOKEN")

	cred := auth.Credential{
		Username: "loresuso",
		Password: token,
	}
	authn.NewClient(cred)

	client := authn.NewClient(cred)

	return client
}

func version(key, pluginName string) string {
	matches := versionRegexp.FindStringSubmatch(key)

	return matches[0]
}

func platform(key, pluginName string) string {
	version := version(key, pluginName)
	index := strings.Index(key, version)
	key = key[index+len(version)+1:]
	key = strings.TrimSuffix(key, ".tar.gz")
	key = strings.Replace(key, "-", "/", 1)

	if !strings.Contains(key, "linux") {
		key = "linux/" + key
	}

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

func loadRegistryFromFile(fname string) (*registry.Registry, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return registry.Load(file)
}
