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

use crate::GcpAuditPlugin;
use falco_plugin::anyhow::{anyhow, Error};
use falco_plugin::event::{PluginEvent, events::Event};
use falco_plugin::extract::{
    field, EventInput, ExtractByteRange, ExtractFieldInfo, ExtractPlugin, ExtractRequest,
};
use serde_spanned::Spanned;
use std::ffi::CString;
use std::ops::Range;

#[derive(Default)]
pub struct GcpAuditContext {
    last_event_num: usize,
    json_value: Option<serde_json::Value>,
    raw_event_data: Vec<u8>,
}

impl GcpAuditPlugin {

    fn ensure_json<'a>(
        context: &'a mut GcpAuditContext,
        event: &EventInput<'_, Event<PluginEvent<&'_ [u8]>>>,
    ) -> Result<&'a serde_json::Value, Error> {
        let event_num = event.event_number();
        if event_num != context.last_event_num || context.json_value.is_none() {
            let evt = event.event()?;
            context.raw_event_data = evt.params.event_data.to_vec();
            context.json_value = Some(serde_json::from_slice(&context.raw_event_data)?);
            context.last_event_num = event_num;
        }
        context.json_value.as_ref().ok_or_else(|| anyhow!("No JSON value parsed"))
    }

    fn do_extract_string(
        context: &mut GcpAuditContext,
        event: &EventInput<'_, Event<PluginEvent<&'_ [u8]>>>,
        path: &str,
    ) -> Result<Option<Spanned<CString>>, Error> {
        let _ = Self::ensure_json(context, event);
        let value = context.json_value.as_ref()
            .and_then(|json| json.pointer(path)?.as_str().map(String::from));
        match value {
            Some(s) => {
                let span = find_json_pointer_range(&context.raw_event_data, path)
                    .unwrap_or(0..0);
                Ok(Some(Spanned::new(span, CString::new(s)?)))
            }
            None => Ok(None),
        }
    }

    fn finish_extract(
        result: Result<Option<Spanned<CString>>, Error>,
        offset: &mut ExtractByteRange,
    ) -> Result<Option<CString>, Error> {
        match result? {
            Some(spanned) => {
                if matches!(*offset, ExtractByteRange::Requested) {
                    let span = spanned.span();
                    if !span.is_empty() {
                        *offset = ExtractByteRange::in_plugin_data(span);
                    }
                }
                Ok(Some(spanned.into_inner()))
            }
            None => Ok(None),
        }
    }

    fn extract_user(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/authenticationInfo/principalEmail"),
            req.offset,
        )
    }

    fn extract_caller_ip(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/requestMetadata/callerIp"),
            req.offset,
        )
    }

    fn extract_user_agent(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/requestMetadata/callerSuppliedUserAgent"),
            req.offset,
        )
    }

    fn extract_authorization_info(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/authorizationInfo"),
            req.offset,
        )
    }

    fn extract_service_name(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/serviceName"),
            req.offset,
        )
    }

    fn extract_policy_delta(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;
        let resource_type = match Self::do_extract_string(context, event, "/resource/type")? {
            Some(v) => v.into_inner(),
            None => return Ok(None),
        };
        let resource_type_str = resource_type.to_str().map_err(|e| anyhow!("{}", e))?;

        let path = if resource_type_str == "gcs_bucket" {
            "/protoPayload/serviceData/policyDelta/bindingDeltas"
        } else {
            "/protoPayload/metadata/datasetChange/bindingDeltas"
        };

        Self::finish_extract(Self::do_extract_string(context, event, path), offset)
    }

    fn extract_request(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/request"),
            req.offset,
        )
    }

    fn extract_method_name(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/methodName"),
            req.offset,
        )
    }

    fn extract_cloudfunctions_function(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/function_name"),
            req.offset,
        )
    }

    fn extract_cloudsql_database_id(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/database_id"),
            req.offset,
        )
    }

    fn extract_compute_instance_id(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/instance_id"),
            req.offset,
        )
    }

    fn extract_compute_network_id(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/network_id"),
            req.offset,
        )
    }

    fn extract_compute_subnetwork(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/subnetwork_name"),
            req.offset,
        )
    }

    fn extract_compute_subnetwork_id(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/subnetwork_id"),
            req.offset,
        )
    }

    fn extract_dns_zone(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/zone_name"),
            req.offset,
        )
    }

    fn extract_iam_service_account(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/email_id"),
            req.offset,
        )
    }

    fn extract_iam_service_account_id(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/unique_id"),
            req.offset,
        )
    }

    fn extract_location(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;
        if let Some(location) = Self::do_extract_string(context, event, "/resource/labels/location")? {
            if matches!(*offset, ExtractByteRange::Requested) {
                let span = location.span();
                if !span.is_empty() {
                    *offset = ExtractByteRange::in_plugin_data(span);
                }
            }
            return Ok(Some(location.into_inner()));
        }
        if let Some(region) = Self::do_extract_string(context, event, "/resource/labels/region")? {
            if matches!(*offset, ExtractByteRange::Requested) {
                let span = region.span();
                if !span.is_empty() {
                    *offset = ExtractByteRange::in_plugin_data(span);
                }
            }
            return Ok(Some(region.into_inner()));
        }
        if let Some(zone) = Self::do_extract_string(context, event, "/resource/labels/zone")? {
            let zone_str = zone.get_ref().to_str().map_err(|e| anyhow!("{}", e))?;
            if zone_str.len() > 2 {
                // Computed value (truncated zone) — no exact byte range
                return Ok(Some(CString::new(&zone_str[..zone_str.len() - 2])?));
            } else if !zone_str.is_empty() {
                if matches!(*offset, ExtractByteRange::Requested) {
                    let span = zone.span();
                    if !span.is_empty() {
                        *offset = ExtractByteRange::in_plugin_data(span);
                    }
                }
                return Ok(Some(zone.into_inner()));
            }
        }
        Ok(None)
    }

    fn extract_logging_sink(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;
        let resource_type = match Self::do_extract_string(context, event, "/resource/type")? {
            Some(v) => v.into_inner(),
            None => return Ok(None),
        };
        let resource_type_str = resource_type.to_str().map_err(|e| anyhow!("{}", e))?;

        if resource_type_str == "logging_sink" {
            Self::finish_extract(Self::do_extract_string(context, event, "/resource/labels/name"), offset)
        } else {
            Ok(None)
        }
    }

    fn extract_project_id(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/project_id"),
            req.offset,
        )
    }

    fn extract_resource_name(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/protoPayload/resourceName"),
            req.offset,
        )
    }

    fn extract_resource_type(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/type"),
            req.offset,
        )
    }

    fn extract_resource_labels(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels"),
            req.offset,
        )
    }

    fn extract_storage_bucket(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/resource/labels/bucket_name"),
            req.offset,
        )
    }

    fn extract_time(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/timestamp"),
            req.offset,
        )
    }

}

impl ExtractPlugin for GcpAuditPlugin {
    type Event<'a> = Event<PluginEvent<&'a [u8]>>;
    type ExtractContext = GcpAuditContext;
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("gcp.user", &Self::extract_user)
            .with_display("User").with_description("GCP principal, actor of the action"),
        field("gcp.callerIP", &Self::extract_caller_ip)
            .with_display("Caller IP").with_description("Actor's IP"),
        field("gcp.userAgent", &Self::extract_user_agent)
            .with_display("User Agent").with_description("Actor's User Agent"),
        field("gcp.authorizationInfo", &Self::extract_authorization_info)
            .with_display("Authorization Info").with_description("GCP authorization (JSON)"),
        field("gcp.serviceName", &Self::extract_service_name)
            .with_display("Service Name").with_description("GCP API service name"),
        field("gcp.policyDelta", &Self::extract_policy_delta)
            .with_display("Policy").with_description("GCP service resource access policy delta"),
        field("gcp.request", &Self::extract_request)
            .with_display("Request").with_description("GCP API raw request (JSON)"),
        field("gcp.methodName", &Self::extract_method_name)
            .with_display("Method").with_description("GCP API service method executed"),
        field("gcp.cloudfunctions.function", &Self::extract_cloudfunctions_function)
            .with_display("Function Name").with_description("GCF name"),
        field("gcp.cloudsql.databaseId", &Self::extract_cloudsql_database_id)
            .with_display("Database ID").with_description("GCP SQL database ID"),
        field("gcp.compute.instanceId", &Self::extract_compute_instance_id)
            .with_display("Instance ID").with_description("GCE instance ID"),
        field("gcp.compute.networkId", &Self::extract_compute_network_id)
            .with_display("Network ID").with_description("GCP network ID"),
        field("gcp.compute.subnetwork", &Self::extract_compute_subnetwork)
            .with_display("Subnetwork Name").with_description("GCP subnetwork name"),
        field("gcp.compute.subnetworkId", &Self::extract_compute_subnetwork_id)
            .with_display("Subnetwork ID").with_description("GCP subnetwork ID"),
        field("gcp.dns.zone", &Self::extract_dns_zone)
            .with_display("DNS Zone").with_description("GCP DNS zone"),
        field("gcp.iam.serviceAccount", &Self::extract_iam_service_account)
            .with_display("Service Account").with_description("GCP service account"),
        field("gcp.iam.serviceAccountId", &Self::extract_iam_service_account_id)
            .with_display("Service Account ID").with_description("GCP IAM unique ID"),
        field("gcp.location", &Self::extract_location)
            .with_display("Location").with_description("GCP region"),
        field("gcp.logging.sink", &Self::extract_logging_sink)
            .with_display("Sink").with_description("GCP logging sink"),
        field("gcp.projectId", &Self::extract_project_id)
            .with_display("Project ID").with_description("GCP project ID"),
        field("gcp.resourceName", &Self::extract_resource_name)
            .with_display("Resource Name").with_description("GCP resource name"),
        field("gcp.resourceType", &Self::extract_resource_type)
            .with_display("Resource Type").with_description("GCP resource type"),
        field("gcp.resourceLabels", &Self::extract_resource_labels)
            .with_display("Resource Labels").with_description("GCP resource labels (JSON)"),
        field("gcp.storage.bucket", &Self::extract_storage_bucket)
            .with_display("Bucket Name").with_description("GCP bucket name"),
        field("gcp.time", &Self::extract_time)
            .with_display("Timestamp of the event").with_description("Timestamp of the event in RFC3339 format"),
    ];

}

// JSON byte-offset helpers for locating values within raw JSON by JSON Pointer path.

fn skip_ws(raw: &[u8], mut pos: usize) -> usize {
    while pos < raw.len() && raw[pos].is_ascii_whitespace() {
        pos += 1;
    }
    pos
}

fn skip_json_string(raw: &[u8], pos: usize) -> Option<usize> {
    if pos >= raw.len() || raw[pos] != b'"' {
        return None;
    }
    let mut p = pos + 1;
    while p < raw.len() {
        match raw[p] {
            b'\\' => p += 2,
            b'"' => return Some(p + 1),
            _ => p += 1,
        }
    }
    None
}

fn read_json_key(raw: &[u8], pos: usize) -> Option<(String, usize)> {
    let end = skip_json_string(raw, pos)?;
    let slice = std::str::from_utf8(&raw[pos..end]).ok()?;
    let key: String = serde_json::from_str(slice).ok()?;
    Some((key, end))
}

fn skip_json_value(raw: &[u8], pos: usize) -> Option<usize> {
    if pos >= raw.len() {
        return None;
    }
    match raw[pos] {
        b'"' => skip_json_string(raw, pos),
        b'{' | b'[' => {
            let mut p = pos + 1;
            let mut depth: u32 = 1;
            while p < raw.len() && depth > 0 {
                match raw[p] {
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => depth -= 1,
                    b'"' => {
                        p = skip_json_string(raw, p)?;
                        continue;
                    }
                    _ => {}
                }
                p += 1;
            }
            Some(p)
        }
        b't' => Some(pos + 4),
        b'f' => Some(pos + 5),
        b'n' => Some(pos + 4),
        _ if raw[pos] == b'-' || raw[pos].is_ascii_digit() => {
            let mut p = pos + 1;
            while p < raw.len()
                && matches!(raw[p], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
            {
                p += 1;
            }
            Some(p)
        }
        _ => None,
    }
}

/// Walk a JSON Pointer path (RFC 6901) through raw JSON bytes and return the
/// byte range of the value found at that path.
fn find_json_pointer_range(raw: &[u8], path: &str) -> Option<Range<usize>> {
    if !path.starts_with('/') {
        return None;
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    let mut pos: usize = 0;

    for (seg_idx, segment) in segments.iter().enumerate() {
        pos = skip_ws(raw, pos);
        if pos >= raw.len() {
            return None;
        }
        let decoded = segment.replace("~1", "/").replace("~0", "~");
        let is_last = seg_idx == segments.len() - 1;

        match raw[pos] {
            b'{' => {
                pos += 1;
                loop {
                    pos = skip_ws(raw, pos);
                    if pos >= raw.len() || raw[pos] == b'}' {
                        return None;
                    }
                    if raw[pos] == b',' {
                        pos += 1;
                        continue;
                    }
                    let (key, key_end) = read_json_key(raw, pos)?;
                    pos = skip_ws(raw, key_end);
                    if pos >= raw.len() || raw[pos] != b':' {
                        return None;
                    }
                    pos = skip_ws(raw, pos + 1);
                    if key == decoded {
                        if is_last {
                            let value_end = skip_json_value(raw, pos)?;
                            return Some(pos..value_end);
                        }
                        break;
                    }
                    pos = skip_json_value(raw, pos)?;
                }
            }
            b'[' => {
                let index: usize = decoded.parse().ok()?;
                pos += 1;
                for i in 0..=index {
                    pos = skip_ws(raw, pos);
                    if pos >= raw.len() || raw[pos] == b']' {
                        return None;
                    }
                    if i > 0 {
                        if raw[pos] != b',' {
                            return None;
                        }
                        pos = skip_ws(raw, pos + 1);
                    }
                    if i == index {
                        if is_last {
                            let value_end = skip_json_value(raw, pos)?;
                            return Some(pos..value_end);
                        }
                        break;
                    }
                    pos = skip_json_value(raw, pos)?;
                }
            }
            _ => return None,
        }
    }
    None
}
