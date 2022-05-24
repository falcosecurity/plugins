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
	MaxEventBytes  uint64 `json:"maxEventBytes"  jsonschema:"description=Max size in bytes for an event JSON payload (Default: 1048576)"`
}

// Resets sets the configuration to its default values
func (k *PluginConfig) Reset() {
	k.MaxEventBytes = 1048576
	k.SSLCertificate = "/etc/falco/falco.pem"
}
