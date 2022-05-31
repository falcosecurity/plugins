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

package k8saudit

type PluginConfig struct {
	SSLCertificate string `json:"sslCertificate" jsonschema:"description=The SSL Certificate to be used with the HTTPS Webhook endpoint (Default: /etc/falco/falco.pem)"`
	MaxEventBytes  uint64 `json:"maxEventBytes"  jsonschema:"description=Max size in bytes for an event JSON payload (Default: 12582912)"`
	UseAsync       bool   `json:"useAsync" jsonschema:"description=If true then async extraction optimization is enabled (Default: true)"`
}

// Resets sets the configuration to its default values
func (k *PluginConfig) Reset() {
	// based on values from: https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/
	k.MaxEventBytes = 12 * 1024 * 1024
	k.SSLCertificate = "/etc/falco/falco.pem"
	k.UseAsync = true
}
