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

// Struct for plugin init config
type PluginConfig struct {
	S3DownloadConcurrency int             `json:"s3DownloadConcurrency" jsonschema:"title=S3 download concurrency,description=Controls the number of background goroutines used to download S3 files (Default: 1),default=1"`
	SQSDelete             bool            `json:"sqsDelete" jsonschema:"title=Delete SQS messages,description=If true then the plugin will delete SQS messages from the queue immediately after receiving them (Default: true),default=true"`
	UseAsync              bool            `json:"useAsync" jsonschema:"title=Use async extraction,description=If true then async extraction optimization is enabled (Default: true),default=true"`
	UseS3SNS              bool            `json:"useS3SNS" jsonschema:"title=Use S3 SNS,description=If true then the plugin will expect SNS messages to originate from S3 instead of directly from Cloudtrail (Default: false),default=false"`
	AWS                   PluginConfigAWS `json:"aws"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	p.SQSDelete = true
	p.S3DownloadConcurrency = 1
	p.UseAsync = true
	p.UseS3SNS = false
	p.AWS.Reset()
}
