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
	S3DownloadConcurrency int  `json:"s3DownloadConcurrency" jsonschema:"description=Controls the number of background goroutines used to download S3 files (Default: 1)"`
	SQSDelete             bool `json:"sqsDelete" jsonschema:"description=If true then the plugin will delete sqs messages from the queue immediately after receiving them (Default: true)"`
	UseAsync              bool `json:"useAsync" jsonschema:"description=If true then async extraction optimization is enabled (Default: true)"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	p.SQSDelete = true
	p.S3DownloadConcurrency = 1
	p.UseAsync = true
}
