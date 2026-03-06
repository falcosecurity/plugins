// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Plugin configuration for the GCP Audit Logs Plugin
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PluginConfig {
    #[serde(rename = "project_id")]
    #[schemars(title = "Project ID", description = "A unique identifier for a GCP project (Default: empty)")]
    pub project_id: String,

    #[serde(rename = "credentials_file")]
    #[schemars(
        title = "Credentials File",
        description = "If non-empty overrides the default GCP credentials file (e.g. ~/.config/gcloud/application_default_credentials.json) and environment variables such as GOOGLE_APPLICATION_CREDENTIALS (Default: empty)"
    )]
    pub credentials_file: String,

    #[serde(rename = "num_goroutines")]
    #[schemars(
        title = "Num Goroutines",
        description = "The number of goroutines that each datastructure along the Receive path will spawn (Default: 10)"
    )]
    pub num_goroutines: i32,

    /// The maximum number of unprocessed messages
    #[serde(rename = "max_outstanding_messages")]
    #[schemars(
        title = "Max Outstanding Messages",
        description = "The maximum number of unprocessed messages (Default: 1000)"
    )]
    pub max_outstanding_messages: i32,

    #[serde(rename = "useAsync")]
    #[schemars(
        title = "Use async extraction (ignored)",
        description = "Ignored. This option is present for compatibility with the original Go version of this plugin."
    )]
    pub use_async: bool,
}

impl Default for PluginConfig {
    fn default() -> Self {
        PluginConfig {
            project_id: String::new(),
            credentials_file: String::new(),
            num_goroutines: 10,
            max_outstanding_messages: 1000,
            use_async: true,
        }
    }
}
