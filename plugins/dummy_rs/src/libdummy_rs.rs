// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
use falco_plugin::anyhow::Error;
use falco_plugin::base::{Json, Plugin};
use falco_plugin::event::events::types::EventType;
use falco_plugin::extract::{EventInput, ExtractFieldInfo, ExtractPlugin, ExtractRequest, field};
use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;
use falco_plugin::source::{EventBatch, PluginEvent, SourcePlugin, SourcePluginInstance};
use falco_plugin::tables::TablesInput;
use falco_plugin::{FailureReason, extract_plugin, plugin, source_plugin};
use rand::Rng;
use rand::rngs::ThreadRng;
use serde_json;
use std::ffi::{CStr, CString};

/// Plugin configuration
#[derive(JsonSchema, Deserialize)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(rename_all = "camelCase", crate = "falco_plugin::serde")]
pub struct Config {
    /// # A random amount added to the sample of each event
    ///
    #[serde(default = "default_jitter")]
    jitter: u64,
}

fn default_jitter() -> u64 {
    10
}

/// Plugin state
pub struct DummyRsPlugin {
    config: Config,
    rng: ThreadRng,
}

impl Plugin for DummyRsPlugin {
    const NAME: &'static CStr = c"dummy_rs";
    const PLUGIN_VERSION: &'static CStr = c"0.1.0";
    const DESCRIPTION: &'static CStr =
        c"Reference plugin for educational purposes, written in Rust";
    const CONTACT: &'static CStr = c"github.com/falcosecurity/plugins";
    type ConfigType = Json<Config>;

    fn new(_input: Option<&TablesInput>, Json(config): Self::ConfigType) -> Result<Self, Error> {
        Ok(Self {
            config,
            rng: rand::thread_rng(),
        })
    }
}

/// Plugin open params
#[derive(JsonSchema, Deserialize)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(rename_all = "camelCase", crate = "falco_plugin::serde")]
pub struct OpenParams {
    start: u64,
    max_events: u64,
}

/// Plugin instance state (i.e. when the capture opens)
pub struct DummyRsPluginInstance {
    max_events: u64,
    counter: u64,
    sample: u64,
}

/// Implement SourcePluginInstance (event source capability)
impl SourcePluginInstance for DummyRsPluginInstance {
    type Plugin = DummyRsPlugin;

    fn next_batch(
        &mut self,
        plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<(), Error> {
        // Stop execution with EOF when max_events is reached
        if self.counter >= self.max_events {
            return Err(FailureReason::Eof.into());
        }
        self.counter += 1;

        // Increment sample by 1, also add a jitter of [0:jitter]
        self.sample += 1 + plugin.rng.gen_range(0..plugin.config.jitter + 1);

        // The representation of a dummy event is the sample as little endian bytes
        let event = self.sample.to_le_bytes().to_vec();

        // Add the encoded sample to the batch
        let event = Self::plugin_event(&event);
        batch.add(event)?;

        Ok(())
    }
}

/// Implement SourcePlugin (event source capability)
impl SourcePlugin for DummyRsPlugin {
    type Instance = DummyRsPluginInstance;
    const EVENT_SOURCE: &'static CStr = c"dummy_rs";
    const PLUGIN_ID: u32 = 23;

    fn open(&mut self, params: Option<&str>) -> Result<Self::Instance, Error> {
        if let Some(json_str) = params {
            let params = serde_json::from_str::<OpenParams>(json_str)?;
            return Ok(Self::Instance {
                max_events: params.max_events,
                counter: 0,
                sample: params.start,
            });
        }
        Err(FailureReason::Failure.into())
    }

    fn event_to_string(&mut self, event: &EventInput) -> Result<CString, Error> {
        let event = event.event()?;
        let event = event.load::<PluginEvent>()?;
        match event.params.event_data {
            Some(payload) => {
                let payload = u64::from_le_bytes(payload.try_into()?);
                Ok(CString::new(format!("{{\"sample\": \"{}\"}}", payload))?)
            }
            None => Ok(CString::new("no event data")?),
        }
    }
}

/// Extraction functions
impl DummyRsPlugin {
    /// Return the sample value in the event, as a u64
    fn extract_value(&mut self, req: ExtractRequest<Self>) -> Result<u64, Error> {
        let event = req.event.event()?;
        let event = event.load::<PluginEvent>()?;
        match event.params.event_data {
            Some(payload) => Ok(u64::from_le_bytes(payload.try_into()?)),
            None => Ok(0),
        }
    }

    /// Return the sample value in the event, as a string
    fn extract_strvalue(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let value = Self::extract_value(self, req)?;
        Ok(CString::new(format!("{}", value))?)
    }
}

/// Implement ExtractPlugin (extraction capability)
impl ExtractPlugin for DummyRsPlugin {
    const EVENT_TYPES: &'static [EventType] = &[];
    const EVENT_SOURCES: &'static [&'static str] = &["dummy_rs"];
    type ExtractContext = ();
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("dummy.value", &Self::extract_value)
            .with_description("The sample value in the event"),
        field("dummy.strvalue", &Self::extract_strvalue)
            .with_description("The sample value in the event, as a string"),
    ];
}

plugin!(DummyRsPlugin);
source_plugin!(DummyRsPlugin);
extract_plugin!(DummyRsPlugin);
