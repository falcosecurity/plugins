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

const (
	PluginNamespace    = "plugins/plugin"
	RulesfileNamespace = "plugins/ruleset"
	RegistryToken      = "REGISTRY_TOKEN"
	RegistryUser       = "REGISTRY_USER"
	RegistryOCI        = "REGISTRY"
	RepoGithub         = "REPO_GITHUB"
	region             = "eu-west-1" // TODO: make it discoverable
	pluginPrefix       = "plugins/stable/"
	maxKeys            = 128
	falcoAuthors       = "The Falco Authors"
	// Architectures as used in the names of the archives uploaded in the S3 bucket.
	x86_arch_s3    = "x86_64"
	arm_aarch64_s3 = "aarch64"
	// Architectures as used in the OCI manifests. We translate the archs from S3 notation to the OCI one.
	amd64OCI       = "amd64"
	arm64OCI       = "arm64"
	archive_suffix = ".tar.gz"
)
