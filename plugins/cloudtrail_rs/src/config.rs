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

/// AWS SDK configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AwsConfig {
    #[serde(rename = "profile")]
    #[schemars(
        title = "AWS Profile",
        description = "If non-empty overrides the AWS shared configuration profile (e.g. 'default') and environment variables such as AWS_PROFILE (Default: empty)"
    )]
    pub profile: String,

    #[serde(rename = "region")]
    #[schemars(
        title = "AWS Region",
        description = "If non-empty overrides the AWS region specified in the profile (e.g. 'us-east-1') and environment variables such as AWS_REGION (Default: empty)"
    )]
    pub region: String,

    #[serde(rename = "config")]
    #[schemars(
        title = "Shared AWS Config File",
        description = "If non-empty overrides the AWS shared configuration filepath (e.g. ~/.aws/config) and env variables such as AWS_CONFIG_FILE (Default: empty)"
    )]
    pub config: String,

    #[serde(rename = "credentials")]
    #[schemars(
        title = "Shared AWS Credentials File",
        description = "If non-empty overrides the AWS shared credentials filepath (e.g. ~/.aws/credentials) and env variables such as AWS_SHARED_CREDENTIALS_FILE (Default: empty)"
    )]
    pub credentials: String,
}

impl Default for AwsConfig {
    fn default() -> Self {
        AwsConfig {
            profile: String::new(),
            region: String::new(),
            config: String::new(),
            credentials: String::new(),
        }
    }
}

/// Plugin configuration for the CloudTrail plugin
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PluginConfig {
    #[serde(rename = "s3DownloadConcurrency")]
    #[schemars(
        title = "S3 download concurrency",
        description = "Controls the number of background goroutines used to download S3 files (Default: 32)"
    )]
    pub s3_download_concurrency: i32,

    #[serde(rename = "s3Interval")]
    #[schemars(
        title = "S3 log interval",
        description = "Download log files over the specified interval (Default: no interval)"
    )]
    pub s3_interval: String,

    #[serde(rename = "sqsDelete")]
    #[schemars(
        title = "Delete SQS messages",
        description = "If true then the plugin will delete SQS messages from the queue immediately after receiving them (Default: true)"
    )]
    pub sqs_delete: bool,

    #[serde(rename = "useAsync")]
    #[schemars(
        title = "Use async extraction (ignored)",
        description = "Ignored. This option is present for compatibility with the original Go version of this plugin."
    )]
    pub use_async: bool,

    #[serde(rename = "useS3SNS")]
    #[schemars(
        title = "Use S3 SNS",
        description = "If true then the plugin will expect SNS messages to originate from S3 instead of directly from Cloudtrail (Default: false)"
    )]
    pub use_s3_sns: bool,

    #[serde(rename = "s3AccountList")]
    #[schemars(
        title = "S3 account list",
        description = "A comma separated list of account IDs for organizational Cloudtrails (Default: no account IDs)"
    )]
    pub s3_account_list: String,

    #[serde(rename = "sqsOwnerAccount")]
    #[schemars(
        title = "SQS owner account",
        description = "The AWS account ID that owns the SQS queue in case the queue is owned by a different account (Default: no account ID)"
    )]
    pub sqs_owner_account: String,

    #[serde(rename = "aws")]
    pub aws: AwsConfig,
}

impl Default for PluginConfig {
    fn default() -> Self {
        PluginConfig {
            s3_download_concurrency: 32,
            s3_interval: String::new(),
            sqs_delete: true,
            use_async: true,
            use_s3_sns: false,
            s3_account_list: String::new(),
            sqs_owner_account: String::new(),
            aws: AwsConfig::default(),
        }
    }
}
