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

package registry

type SourcingCapability struct {
	Supported bool   `yaml:"supported"`
	ID        uint   `yaml:"id"`
	Source    string `yaml:"source"`
}

type ExtractionCapability struct {
	Supported bool     `yaml:"supported"`
	Sources   []string `yaml:"sources"`
}

type Capabilities struct {
	Sourcing   SourcingCapability   `yaml:"sourcing"`
	Extraction ExtractionCapability `yaml:"extraction"`
}

type Plugin struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Authors     string `yaml:"authors"`
	Contact     string `yaml:"contact"`
	Maintainers []struct {
		Email string `yaml:"email"`
		Name  string `yaml:"name"`
	} `yaml:"maintainers"`
	Keywords     []string     `yaml:"keywords"`
	URL          string       `yaml:"url"`
	RulesURL     string       `yaml:"rules_url"`
	License      string       `yaml:"license"`
	Reserved     bool         `yaml:"reserved"`
	Capabilities Capabilities `yaml:"capabilities"`
}

type Registry struct {
	Plugins         []Plugin `yaml:"plugins"`
	ReservedSources []string `yaml:"reserved_sources"`
}

type ArtifactsPushStatus []ArtifactPushMetadata

// ArtifactPushMetadata represents metadata of a push of an OCI Artifact to
// an OCI repository.
type ArtifactPushMetadata struct {
	Repository RepositoryMetadata `json:"repository"`
	Artifact   ArtifactMetadata   `json:"artifact"`
}

type ArtifactMetadata struct {
	Digest string   `json:"digest"`
	Tags   []string `json:"tags"`
}

type RepositoryMetadata struct {
	Ref string `json:"ref"`
}
