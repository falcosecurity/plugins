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

use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, Result};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_sqs::Client as SqsClient;
use aws_types::SdkConfig;
use falco_plugin::source::{EventBatch, SourcePluginInstance};
use regex::Regex;
use tokio::runtime::Runtime;

use crate::config::PluginConfig;
use crate::interval::parse_interval;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    File,
    S3,
    Sqs,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub is_compressed: bool,
}

struct S3State {
    bucket: String,
    client: S3Client,
    download_bufs: Vec<Vec<u8>>,
    last_downloaded_file_num: usize,
    n_filled_bufs: usize,
    cur_buf: usize,
}

struct SqsState {
    client: SqsClient,
    queue_url: String,
}

pub struct CloudTrailInstance {
    mode: OpenMode,
    config: PluginConfig,
    files: Vec<FileInfo>,
    cur_file_num: usize,
    evt_json_strings: Vec<Vec<u8>>,
    evt_json_list_pos: usize,
    s3_state: Option<S3State>,
    sqs_state: Option<SqsState>,
    runtime: Option<Runtime>,
}

/// Extract individual record entries from a CloudTrail JSON file.
/// CloudTrail files have the format: {"Records":[{evt1},{evt2},...]}
/// We split at the top-level record boundaries to preserve original JSON.
fn extract_record_strings(json_str: &[u8], res: &mut Vec<Vec<u8>>) {
    let mut depth: i32 = 0;
    let mut entry_start: usize = 0;
    let mut in_string = false;
    let mut escape = false;

    for (pos, &ch) in json_str.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if in_string {
            if ch == b'\\' {
                escape = true;
            } else if ch == b'"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            b'"' => in_string = true,
            b'{' => {
                if depth == 1 {
                    entry_start = pos;
                }
                depth += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 1 && pos < json_str.len() - 1 {
                    res.push(json_str[entry_start..=pos].to_vec());
                }
            }
            _ => {}
        }
    }
}

impl CloudTrailInstance {
    pub fn open_local(params: &str, config: &PluginConfig) -> Result<Self> {
        if params.is_empty() {
            return Err(anyhow!("cloudtrail plugin error: missing input directory argument"));
        }

        let path = Path::new(params);
        if !path.exists() {
            return Err(anyhow!(
                "cloudtrail plugin error: cannot open {}",
                params
            ));
        }

        let mut files = Vec::new();
        collect_local_files(path, &mut files)?;

        if files.is_empty() {
            return Err(anyhow!(
                "cloudtrail plugin error: no json files found in {}",
                params
            ));
        }

        Ok(CloudTrailInstance {
            mode: OpenMode::File,
            config: config.clone(),
            files,
            cur_file_num: 0,
            evt_json_strings: Vec::new(),
            evt_json_list_pos: 0,
            s3_state: None,
            sqs_state: None,
            runtime: None,
        })
    }

    pub fn open_s3(
        params: &str,
        config: &PluginConfig,
        aws_config: SdkConfig,
        runtime: Runtime,
    ) -> Result<Self> {
        if config.s3_download_concurrency < 1 {
            return Err(anyhow!(
                "cloudtrail invalid S3DownloadConcurrency: \"{}\"",
                config.s3_download_concurrency
            ));
        }

        // Remove "s3://" prefix
        let input = &params[5..];
        let (bucket, prefix) = match input.find('/') {
            Some(idx) => (input[..idx].to_string(), input[idx + 1..].to_string()),
            None => (input.to_string(), String::new()),
        };

        let s3_client = S3Client::new(&aws_config);
        let download_bufs = vec![Vec::new(); config.s3_download_concurrency as usize];

        let s3_state = S3State {
            bucket: bucket.clone(),
            client: s3_client,
            download_bufs,
            last_downloaded_file_num: 0,
            n_filled_bufs: 0,
            cur_buf: 0,
        };

        let mut inst = CloudTrailInstance {
            mode: OpenMode::S3,
            config: config.clone(),
            files: Vec::new(),
            cur_file_num: 0,
            evt_json_strings: Vec::new(),
            evt_json_list_pos: 0,
            s3_state: Some(s3_state),
            sqs_state: None,
            runtime: Some(runtime),
        };

        // List S3 keys
        inst.list_s3_keys(&bucket, &prefix)?;

        Ok(inst)
    }

    pub fn open_sqs(
        params: &str,
        config: &PluginConfig,
        aws_config: SdkConfig,
        runtime: Runtime,
    ) -> Result<Self> {
        let sqs_client = SqsClient::new(&aws_config);
        let s3_client = S3Client::new(&aws_config);

        let queue_name = &params[6..];

        // Get the queue URL
        let queue_url = {
            let mut req = sqs_client.get_queue_url().queue_name(queue_name);
            if !config.sqs_owner_account.is_empty() {
                req = req.queue_owner_aws_account_id(&config.sqs_owner_account);
            }
            let result = runtime.block_on(req.send())?;
            result
                .queue_url()
                .ok_or_else(|| anyhow!("failed to get queue URL"))?
                .to_string()
        };

        let download_bufs = vec![Vec::new(); config.s3_download_concurrency as usize];

        let s3_state = S3State {
            bucket: String::new(),
            client: s3_client,
            download_bufs,
            last_downloaded_file_num: 0,
            n_filled_bufs: 0,
            cur_buf: 0,
        };

        let sqs_state = SqsState {
            client: sqs_client,
            queue_url,
        };

        let mut inst = CloudTrailInstance {
            mode: OpenMode::Sqs,
            config: config.clone(),
            files: Vec::new(),
            cur_file_num: 0,
            evt_json_strings: Vec::new(),
            evt_json_list_pos: 0,
            s3_state: Some(s3_state),
            sqs_state: Some(sqs_state),
            runtime: Some(runtime),
        };

        // Get initial batch of SQS files
        inst.get_more_sqs_files()?;

        Ok(inst)
    }

    fn list_s3_keys(&mut self, bucket: &str, prefix: &str) -> Result<()> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| anyhow!("no runtime"))?;
        let s3 = self
            .s3_state
            .as_ref()
            .ok_or_else(|| anyhow!("no S3 state"))?;

        let (start_time, end_time) = parse_interval(&self.config.s3_interval)?;

        let start_ts_format = "%Y%m%dT%H%M";
        let start_ts = start_time.map(|t| t.format(start_ts_format).to_string());
        let end_ts = end_time.map(|t| t.format(start_ts_format).to_string());

        if let (Some(ref s), Some(ref e)) = (&start_ts, &end_ts) {
            if e < s {
                return Err(anyhow!(
                    "cloudtrail start time must be less than end time"
                ));
            }
        }

        let account_list_re = Regex::new(r"^(?: *\d{12} *,?)*$")?;
        if !self.config.s3_account_list.is_empty()
            && !account_list_re.is_match(&self.config.s3_account_list)
        {
            return Err(anyhow!(
                "cloudtrail invalid account list: \"{}\"",
                self.config.s3_account_list
            ));
        }

        // Determine the prefixes to list based on the CloudTrail path structure
        let aws_logs_re = Regex::new(r"/AWSLogs/(?:o-[a-z0-9]{10,32}/)?\d{12}/?$")?;
        let aws_logs_org_re = Regex::new(r"/AWSLogs(?:/o-[a-z0-9]{10,32})?/?$")?;

        let mut interval_prefix_list: Vec<String> = Vec::new();
        let mut interval_prefix = prefix.to_string();

        if aws_logs_re.is_match(&interval_prefix) {
            if !interval_prefix.ends_with('/') {
                interval_prefix.push('/');
            }
            interval_prefix.push_str("CloudTrail/");
            interval_prefix_list.push(interval_prefix);
        } else if aws_logs_org_re.is_match(&interval_prefix) {
            if !interval_prefix.ends_with('/') {
                interval_prefix.push('/');
            }
            if !self.config.s3_account_list.is_empty() {
                for account in self.config.s3_account_list.split(',') {
                    let account = account.trim();
                    interval_prefix_list
                        .push(format!("{}{}/CloudTrail/", interval_prefix, account));
                }
            } else {
                // List account IDs from the bucket
                let accounts = runtime.block_on(list_common_prefixes(
                    &s3.client,
                    bucket,
                    &interval_prefix,
                ))?;
                for acct_prefix in accounts {
                    if aws_logs_re.is_match(&acct_prefix) {
                        interval_prefix_list.push(format!("{}CloudTrail/", acct_prefix));
                    }
                }
            }
        } else {
            interval_prefix_list.push(interval_prefix);
        }

        // For each prefix, list regions and then list keys
        let mut input_prefixes: Vec<(String, Option<String>)> = Vec::new();

        for ip in &interval_prefix_list {
            if ip.ends_with("/CloudTrail/") {
                let regions =
                    runtime.block_on(list_common_prefixes(&s3.client, bucket, ip))?;
                for region_prefix in regions {
                    let start_after = start_time.map(|t| {
                        format!("{}{}", region_prefix, t.format("%Y/%m/%d/"))
                    });
                    input_prefixes.push((region_prefix, start_after));
                }
            }
        }

        if input_prefixes.is_empty() {
            input_prefixes.push((prefix.to_string(), None));
        }

        // List keys for all prefixes
        let filepath_re = Regex::new(r".*_CloudTrail_[^_]+_([^_]+)Z_")?;

        for (pfx, start_after) in &input_prefixes {
            let keys = runtime.block_on(list_s3_keys(
                &s3.client,
                bucket,
                pfx,
                start_after.as_deref(),
            ))?;

            for key in keys {
                // Apply interval filter based on filepath timestamp
                if let Some(ref sts) = start_ts {
                    if let Some(caps) = filepath_re.captures(&key) {
                        let path_ts = &caps[1];
                        if path_ts < sts.as_str() {
                            continue;
                        }
                        if let Some(ref ets) = end_ts {
                            if path_ts > ets.as_str() {
                                continue;
                            }
                        }
                    }
                }

                let is_compressed = key.ends_with(".json.gz");
                if !key.ends_with(".json") && !is_compressed {
                    continue;
                }

                self.files.push(FileInfo {
                    name: key,
                    is_compressed,
                });
            }
        }

        Ok(())
    }

    fn get_more_sqs_files(&mut self) -> Result<()> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| anyhow!("no runtime"))?;
        let sqs = self
            .sqs_state
            .as_ref()
            .ok_or_else(|| anyhow!("no SQS state"))?;

        let result = runtime.block_on(
            sqs.client
                .receive_message()
                .queue_url(&sqs.queue_url)
                .max_number_of_messages(1)
                .send(),
        )?;

        let messages = result.messages();
        if messages.is_empty() {
            return Ok(());
        }

        let message = &messages[0];

        // Delete the message if configured
        if self.config.sqs_delete {
            if let Some(receipt_handle) = message.receipt_handle() {
                let _ = runtime.block_on(
                    sqs.client
                        .delete_message()
                        .queue_url(&sqs.queue_url)
                        .receipt_handle(receipt_handle)
                        .send(),
                );
            }
        }

        let body = message
            .body()
            .ok_or_else(|| anyhow!("SQS message has no body"))?;
        let sqs_msg: serde_json::Value = serde_json::from_str(body)?;

        let msg_type = sqs_msg
            .get("Type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("received SQS message that did not have a Type property"))?;

        if msg_type != "Notification" {
            return Err(anyhow!(
                "received SQS message that was not a SNS Notification"
            ));
        }

        let sns_message = sqs_msg
            .get("Message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("SNS notification missing Message field"))?;

        if self.config.use_s3_sns {
            // Process SNS message coming from S3
            let s3_event: serde_json::Value = serde_json::from_str(sns_message)?;
            let records = s3_event
                .get("Records")
                .and_then(|v| v.as_array())
                .ok_or_else(|| anyhow!("S3 event missing Records"))?;

            for record in records {
                let bucket_name = record
                    .pointer("/s3/bucket/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let key = record
                    .pointer("/s3/object/key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                if let Some(s3) = self.s3_state.as_mut() {
                    s3.bucket = bucket_name.to_string();
                }

                let is_compressed = key.ends_with(".json.gz");
                self.files.push(FileInfo {
                    name: key.to_string(),
                    is_compressed,
                });
            }
        } else {
            // Process direct CloudTrail SNS notification
            #[derive(serde::Deserialize)]
            struct SnsMessage {
                #[serde(rename = "s3Bucket")]
                bucket: String,
                #[serde(rename = "s3ObjectKey")]
                keys: Vec<String>,
            }

            let notification: SnsMessage = serde_json::from_str(sns_message)?;

            if let Some(s3) = self.s3_state.as_mut() {
                s3.bucket = notification.bucket;
            }

            for key in notification.keys {
                let is_compressed = key.ends_with(".json.gz");
                self.files.push(FileInfo {
                    name: key,
                    is_compressed,
                });
            }
        }

        Ok(())
    }

    fn read_next_file_s3(&mut self) -> Result<Vec<u8>> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| anyhow!("no runtime"))?;
        let s3 = self
            .s3_state
            .as_mut()
            .ok_or_else(|| anyhow!("no S3 state"))?;

        // Check if we still have buffered data
        if s3.cur_buf < s3.n_filled_bufs {
            let buf = std::mem::take(&mut s3.download_bufs[s3.cur_buf]);
            s3.cur_buf += 1;
            return Ok(buf);
        }

        // Download the next batch of files concurrently
        let k = s3.last_downloaded_file_num;
        let concurrency = self.config.s3_download_concurrency as usize;
        let n_to_download = std::cmp::min(concurrency, self.files.len() - k);

        let bucket = s3.bucket.clone();
        let files_to_download: Vec<String> = self.files[k..k + n_to_download]
            .iter()
            .map(|f| f.name.clone())
            .collect();

        let client = s3.client.clone();
        let results = runtime.block_on(async {
            let mut handles = Vec::new();
            for key in files_to_download {
                let client = client.clone();
                let bucket = bucket.clone();
                handles.push(tokio::spawn(async move {
                    let result = client
                        .get_object()
                        .bucket(&bucket)
                        .key(&key)
                        .send()
                        .await?;
                    let data = result.body.collect().await?;
                    Ok::<Vec<u8>, anyhow::Error>(data.into_bytes().to_vec())
                }));
            }
            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.await??);
            }
            Ok::<Vec<Vec<u8>>, anyhow::Error>(results)
        })?;

        let s3 = self
            .s3_state
            .as_mut()
            .ok_or_else(|| anyhow!("no S3 state"))?;

        s3.n_filled_bufs = results.len();
        for (i, buf) in results.into_iter().enumerate() {
            s3.download_bufs[i] = buf;
        }
        s3.last_downloaded_file_num += s3.n_filled_bufs;
        s3.cur_buf = 1;

        let buf = std::mem::take(&mut s3.download_bufs[0]);
        Ok(buf)
    }

    /// Core event production: loads the next event from the current or next file.
    fn next_event(&mut self) -> Result<Option<Vec<u8>>> {
        // Check if we still have events from the current file
        if self.evt_json_list_pos < self.evt_json_strings.len() {
            let evt_data = self.evt_json_strings[self.evt_json_list_pos].clone();
            self.evt_json_list_pos += 1;

            // Validate the event has required fields
            if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&evt_data) {
                // Skip events without eventTime
                if parsed.get("eventTime").is_none() {
                    return Ok(None); // skip
                }
                // Skip AwsCloudTrailInsight events
                if parsed
                    .get("eventType")
                    .and_then(|v| v.as_str())
                    == Some("AwsCloudTrailInsight")
                {
                    return Ok(None); // skip
                }
            }

            return Ok(Some(evt_data));
        }

        // Need to read the next file
        if self.cur_file_num >= self.files.len() {
            if self.mode == OpenMode::Sqs {
                self.get_more_sqs_files()?;
                if self.cur_file_num >= self.files.len() {
                    return Ok(None); // no more files yet
                }
            } else {
                return Err(anyhow!("EOF"));
            }
        }

        let file = self.files[self.cur_file_num].clone();
        self.cur_file_num += 1;

        // Read the file content
        let raw_data = match self.mode {
            OpenMode::S3 | OpenMode::Sqs => self.read_next_file_s3()?,
            OpenMode::File => std::fs::read(&file.name)?,
        };

        // Decompress if gzipped
        let data = if file.is_compressed {
            let mut decoder = flate2::read::GzDecoder::new(&raw_data[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        } else {
            raw_data
        };

        // Extract individual records from the CloudTrail JSON
        self.evt_json_strings.clear();
        extract_record_strings(&data, &mut self.evt_json_strings);
        self.evt_json_list_pos = 0;

        // Recurse to get the first event from this file
        self.next_event()
    }
}

impl SourcePluginInstance for CloudTrailInstance {
    type Plugin = crate::CloudTrailPlugin;

    fn next_batch(
        &mut self,
        _plugin: &mut Self::Plugin,
        batch: &mut EventBatch,
    ) -> Result<()> {
        match self.next_event() {
            Ok(Some(data)) => {
                batch.add(Self::plugin_event(&data))?;
                Ok(())
            }
            Ok(None) => {
                // No events available right now (timeout equivalent)
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

fn collect_local_files(dir: &Path, files: &mut Vec<FileInfo>) -> Result<()> {
    if dir.is_file() {
        let name = dir.to_string_lossy().to_string();
        let is_compressed = name.ends_with(".json.gz");
        if name.ends_with(".json") || is_compressed {
            files.push(FileInfo {
                name,
                is_compressed,
            });
        }
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_local_files(&path, files)?;
        } else {
            let name = path.to_string_lossy().to_string();
            let is_compressed = name.ends_with(".json.gz");
            if name.ends_with(".json") || is_compressed {
                files.push(FileInfo {
                    name,
                    is_compressed,
                });
            }
        }
    }

    Ok(())
}

async fn list_common_prefixes(
    client: &S3Client,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<String>> {
    let mut prefixes = Vec::new();
    let mut continuation_token: Option<String> = None;

    loop {
        let mut req = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix)
            .delimiter("/");

        if let Some(token) = continuation_token {
            req = req.continuation_token(token);
        }

        let output = req.send().await?;

        for cp in output.common_prefixes() {
            if let Some(p) = cp.prefix() {
                prefixes.push(p.to_string());
            }
        }

        if output.is_truncated() == Some(true) {
            continuation_token = output.next_continuation_token().map(|s| s.to_string());
        } else {
            break;
        }
    }

    Ok(prefixes)
}

async fn list_s3_keys(
    client: &S3Client,
    bucket: &str,
    prefix: &str,
    start_after: Option<&str>,
) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    let mut continuation_token: Option<String> = None;

    loop {
        let mut req = client.list_objects_v2().bucket(bucket).prefix(prefix);

        if let Some(sa) = start_after {
            req = req.start_after(sa);
        }

        if let Some(token) = continuation_token {
            req = req.continuation_token(token);
        }

        let output = req.send().await?;

        for obj in output.contents() {
            if let Some(key) = obj.key() {
                keys.push(key.to_string());
            }
        }

        if output.is_truncated() == Some(true) {
            continuation_token = output.next_continuation_token().map(|s| s.to_string());
        } else {
            break;
        }
    }

    Ok(keys)
}
