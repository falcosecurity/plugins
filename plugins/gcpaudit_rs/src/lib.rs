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
use config::PluginConfig;
use falco_plugin::base::{Json, Plugin};
use falco_plugin::event::{PluginEvent, events::Event};
use falco_plugin::source::{EventInput, SourcePlugin};
use falco_plugin::tables::TablesInput;
use falco_plugin::{extract_plugin, plugin, source_plugin};
use source::GcpAuditInstance;

pub mod config;
mod extract;
mod source;

pub struct GcpAuditPlugin {
    config: PluginConfig,
}

impl GcpAuditPlugin {
    pub fn new(config: PluginConfig) -> Self {
        GcpAuditPlugin { config }
    }
}

impl Plugin for GcpAuditPlugin {
    const NAME: &'static CStr = c"gcpaudit";
    const PLUGIN_VERSION: &'static CStr = c"0.1.0";
    const DESCRIPTION: &'static CStr = c"Read GCP Audit Logs";
    const CONTACT: &'static CStr = c"github.com/falcosecurity/plugins";
    type ConfigType = Json<PluginConfig>;

    fn new(_input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self> {
        Ok(GcpAuditPlugin { config: config.0 })
    }

    fn set_config(&mut self, config: Self::ConfigType) -> Result<()> {
        self.config = config.0;
        Ok(())
    }
}

impl SourcePlugin for GcpAuditPlugin {
    type Instance = GcpAuditInstance;
    type Event<'a> = Event<PluginEvent<&'a [u8]>>;
    const EVENT_SOURCE: &'static CStr = c"gcpaudit";
    const PLUGIN_ID: u32 = 12;

    fn open(&mut self, params: Option<&str>) -> Result<Self::Instance> {
        let subscription_id = params
            .ok_or_else(|| anyhow!("no subscriptionID provided"))?
            .to_string();

        GcpAuditInstance::new(self.config.clone(), subscription_id)
    }

    fn event_to_string(&mut self, event: &EventInput<Self::Event<'_>>) -> Result<CString> {
        let evt = event.event()?;
        Ok(CString::new(evt.params.event_data.to_vec())?)
    }
}

plugin!{GcpAuditPlugin}
source_plugin!(GcpAuditPlugin);
extract_plugin!(GcpAuditPlugin);
