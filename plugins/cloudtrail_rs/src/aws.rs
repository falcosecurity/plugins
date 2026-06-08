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

use anyhow::Result;
use aws_types::region::Region;
use aws_types::SdkConfig;

use crate::config::AwsConfig;

/// Load the AWS SDK config from the given AwsConfig settings
pub async fn load_aws_config(aws: &AwsConfig) -> Result<SdkConfig> {
    // Apply config and credentials file overrides via env vars.
    // Safety: called once during initialization before any concurrent access.
    if !aws.config.is_empty() {
        unsafe {
            std::env::set_var("AWS_CONFIG_FILE", &aws.config);
        }
    }
    if !aws.credentials.is_empty() {
        unsafe {
            std::env::set_var("AWS_SHARED_CREDENTIALS_FILE", &aws.credentials);
        }
    }

    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

    if !aws.profile.is_empty() {
        loader = loader.profile_name(&aws.profile);
    }

    if !aws.region.is_empty() {
        loader = loader.region(Region::new(aws.region.clone()));
    }

    Ok(loader.load().await)
}
