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

package cloudtrail

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// PluginConfigAWS contains configuration options for the AWS SDK.
// This can be included in plugins' init configuration struct definition
// to declare AWS-specific config fields
type PluginConfigAWS struct {
	Profile     string `json:"profile" jsonschema:"title=AWS Profile,description=If non-empty overrides the AWS shared configuration profile (e.g. 'default') and environment variables such as AWS_PROFILE (Default: empty),default="`
	Region      string `json:"region" jsonschema:"title=AWS Region,description=If non-empty overrides the AWS region specified in the profile (e.g. 'us-east-1') and environment variables such as AWS_REGION (Default: empty),default="`
	Config      string `json:"config" jsonschema:"title=Shared AWS Config File,description=If non-empty overrides the AWS shared configuration filepath (e.g. ~/.aws/config) and env variables such as AWS_CONFIG_FILE (Default: empty),default="`
	Credentials string `json:"credentials" jsonschema:"title=Shared AWS Credentials File,description=If non-empty overrides the AWS shared credentials filepath (e.g. ~/.aws/credentials) and env variables such as AWS_SHARED_CREDENTIALS_FILE (Default: empty),default="`
}

// Reset sets the configuration to its default values
func (p *PluginConfigAWS) Reset() {
	p.Profile = ""
	p.Region = ""
	p.Config = ""
	p.Credentials = ""
}

// ConfigAWS creates loads the AWS SDK config by using the contents of
// the given PluginConfigAWS
func (p *PluginConfigAWS) ConfigAWS() (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	if len(p.Profile) > 0 {
		opts = append(opts, config.WithSharedConfigProfile(p.Profile))
	}

	if len(p.Region) > 0 {
		opts = append(opts, config.WithRegion(p.Region))
	}

	if len(p.Config) > 0 {
		opts = append(opts, config.WithSharedConfigFiles([]string{p.Config}))
	}

	if len(p.Credentials) > 0 {
		opts = append(opts, config.WithSharedCredentialsFiles([]string{p.Credentials}))
	}

	ctx := context.Background()
	return config.LoadDefaultConfig(ctx, opts...)
}
