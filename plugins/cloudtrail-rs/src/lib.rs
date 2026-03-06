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

use std::ffi::{CStr, CString};

use anyhow::{anyhow, Result};
use aws_types::SdkConfig;
use config::PluginConfig;
use falco_plugin::base::{Json, Plugin};
use falco_plugin::event::{PluginEvent, events::Event};
use falco_plugin::source::{EventInput, SourcePlugin};
use falco_plugin::tables::TablesInput;
use falco_plugin::{extract_plugin, plugin, source_plugin};
use source::CloudTrailInstance;
use tokio::runtime::Runtime;

pub mod config;
mod aws;
mod extract;
mod interval;
mod source;

pub struct CloudTrailPlugin {
    config: PluginConfig,
    aws_config: SdkConfig,
}

impl Plugin for CloudTrailPlugin {
    const NAME: &'static CStr = c"cloudtrail";
    const PLUGIN_VERSION: &'static CStr = c"0.14.0";
    const DESCRIPTION: &'static CStr =
        c"reads cloudtrail JSON data saved to file in the directory specified in the settings";
    const CONTACT: &'static CStr = c"github.com/falcosecurity/plugins/";
    type ConfigType = Json<PluginConfig>;

    fn new(_input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self> {
        let config = config.0;
        let rt = Runtime::new()?;
        let aws_config = rt.block_on(aws::load_aws_config(&config.aws))?;
        Ok(CloudTrailPlugin { config, aws_config })
    }

    fn set_config(&mut self, config: Self::ConfigType) -> Result<()> {
        self.config = config.0;
        let rt = Runtime::new()?;
        self.aws_config = rt.block_on(aws::load_aws_config(&self.config.aws))?;
        Ok(())
    }
}

impl SourcePlugin for CloudTrailPlugin {
    type Instance = CloudTrailInstance;
    type Event<'a> = Event<PluginEvent<&'a [u8]>>;
    const EVENT_SOURCE: &'static CStr = c"aws_cloudtrail";
    const PLUGIN_ID: u32 = 2;

    fn open(&mut self, params: Option<&str>) -> Result<Self::Instance> {
        let params = params
            .ok_or_else(|| anyhow!("no input provided"))?;

        if params.starts_with("s3://") {
            let runtime = Runtime::new()?;
            let aws_config = self.aws_config.clone();
            CloudTrailInstance::open_s3(params, &self.config, aws_config, runtime)
        } else if params.starts_with("sqs://") {
            let runtime = Runtime::new()?;
            let aws_config = self.aws_config.clone();
            CloudTrailInstance::open_sqs(params, &self.config, aws_config, runtime)
        } else {
            CloudTrailInstance::open_local(params, &self.config)
        }
    }

    fn event_to_string(&mut self, event: &EventInput<Self::Event<'_>>) -> Result<CString> {
        let evt = event.event()?;
        Ok(CString::new(evt.params.event_data.to_vec())?)
    }
}

plugin!(CloudTrailPlugin);
source_plugin!(CloudTrailPlugin);
extract_plugin!(CloudTrailPlugin);
