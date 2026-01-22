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
// use google_cloud_googleapis::pubsub::v1::PubsubMessage;
use google_cloud_pubsub::client::{Client, ClientConfig};
use google_cloud_pubsub::subscription::SubscriptionConfig;
// use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use crate::config::PluginConfig;

const MAX_RETRIES: u32 = 3;
const INITIAL_RETRY_DELAY_MS: u64 = 1000;

pub struct GcpAuditInstance {
    runtime: Runtime,
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
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

        Ok(GcpAuditInstance { runtime, receiver })
    }

    async fn pull_messages_async(
        config: PluginConfig,
        subscription_id: String,
        sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<()> {
        // Create client configuration
        let client_config = ClientConfig::default();
        
        // Apply credentials file if specified
        if !config.credentials_file.is_empty() {
            // Note: The exact API for setting credentials file may differ
            // based on the google-cloud-pubsub crate version
            std::env::set_var("GOOGLE_APPLICATION_CREDENTIALS", &config.credentials_file);
        }

        // Create PubSub client
        let client = Client::new(client_config).await?;

        // Configure subscription settings
        let subscription = client.subscription(&subscription_id);
        
        let mut retry_delay = Duration::from_millis(INITIAL_RETRY_DELAY_MS);
        
        for _retry in 0..MAX_RETRIES {
            match Self::perform_pubsub_operation(&subscription, &sender, &config).await {
                Ok(_) => return Ok(()),
                Err(e) if Self::is_quota_exceeded_error(&e) => {
                    eprintln!(
                        "[gcpaudit] pubsub receive quota exceeded, retrying in {:?}",
                        retry_delay
                    );
                    tokio::time::sleep(retry_delay).await;
                    retry_delay *= 2; // exponential backoff
                }
                Err(e) => {
                    return Err(anyhow!("PubSub operation failed: {}", e));
                }
            }
        }

        Err(anyhow!("Max retries exceeded"))
    }

    async fn perform_pubsub_operation(
        subscription: &google_cloud_pubsub::subscription::Subscription,
        sender: &mpsc::UnboundedSender<Vec<u8>>,
        config: &PluginConfig,
    ) -> Result<()> {
        // Configure receive settings
        let mut receive_config = SubscriptionConfig::default();
        receive_config.max_outstanding_messages = config.max_outstanding_messages as i64;
        
        // Receive messages
        loop {
            let messages = subscription.receive(1, None).await?;
            
            for (_ack_id, message) in messages {
                // Send message data to channel
                if sender.send(message.message.data.clone()).is_err() {
                    return Err(anyhow!("Failed to send message to channel"));
                }
                
                // Acknowledge the message
                if let Err(e) = message.ack().await {
                    eprintln!("[gcpaudit] Failed to acknowledge message: {}", e);
                }
            }
        }
    }

    fn is_quota_exceeded_error(error: &anyhow::Error) -> bool {
        error.to_string().contains("quota exceeded")
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
                batch.add(data)?;
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
