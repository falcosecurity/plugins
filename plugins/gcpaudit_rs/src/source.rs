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

use anyhow::{anyhow, Result};
use falco_plugin::source::{EventBatch, SourcePluginInstance};
use google_cloud_pubsub::client::{Client, ClientConfig};
use google_cloud_pubsub::subscriber::{ReceivedMessage, SubscriberConfig};
use google_cloud_pubsub::subscription::ReceiveConfig;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use crate::config::PluginConfig;

pub struct GcpAuditInstance {
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    // Runtime must be held to keep the background task alive
    _runtime: Runtime,
}

impl GcpAuditInstance {
    pub fn new(config: PluginConfig, subscription_id: String) -> Result<Self> {
        let runtime = Runtime::new()?;
        let (sender, receiver) = mpsc::unbounded_channel();

        // Spawn the PubSub message receiver in the background
        runtime.spawn(async move {
            if let Err(e) = Self::pull_messages_async(config, subscription_id, sender).await {
                eprintln!("[gcpaudit] Error pulling messages: {}", e);
            }
        });

        Ok(GcpAuditInstance { receiver, _runtime: runtime })
    }

    async fn pull_messages_async(
        config: PluginConfig,
        subscription_id: String,
        sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<()> {
        let client_config = ClientConfig::default();

        // Apply credentials file if specified
        if !config.credentials_file.is_empty() {
            // Safety: this is called once during initialization before the
            // async receive loop starts, so there is no concurrent access.
            unsafe {
                std::env::set_var("GOOGLE_APPLICATION_CREDENTIALS", &config.credentials_file);
            }
        }

        let client = Client::new(client_config).await?;
        let subscription = client.subscription(&subscription_id);
        let cancel = CancellationToken::new();

        let receive_config = ReceiveConfig {
            worker_count: config.num_goroutines.max(1) as usize,
            subscriber_config: Some(SubscriberConfig {
                max_outstanding_messages: config.max_outstanding_messages as i64,
                ..Default::default()
            }),
            ..Default::default()
        };

        subscription
            .receive(
                move |message: ReceivedMessage, _cancel: CancellationToken| {
                    let sender = sender.clone();
                    async move {
                        if sender.send(message.message.data.to_vec()).is_ok() {
                            if let Err(e) = message.ack().await {
                                eprintln!("[gcpaudit] Failed to acknowledge message: {}", e);
                            }
                        }
                    }
                },
                cancel,
                Some(receive_config),
            )
            .await
            .map_err(|e| anyhow!("PubSub receive failed: {}", e))?;

        Ok(())
    }
}

impl SourcePluginInstance for GcpAuditInstance {
    type Plugin = crate::GcpAuditPlugin;

    fn next_batch(
        &mut self,
        _plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<()> {
        // Try to receive a message from the channel
        match self.receiver.try_recv() {
            Ok(data) => {
                batch.add(Self::plugin_event(&data))?;
                Ok(())
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // No events available, return empty batch
                Ok(())
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(anyhow!("PubSub message channel disconnected"))
            }
        }
    }
}
