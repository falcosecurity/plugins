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

use crate::CloudTrailPlugin;
use falco_plugin::anyhow::{anyhow, Error};
use falco_plugin::event::{PluginEvent, events::Event};
use falco_plugin::extract::{
    field, EventInput, ExtractByteRange, ExtractFieldInfo, ExtractPlugin, ExtractRequest,
};
use serde_spanned::Spanned;
use std::ffi::CString;
use std::ops::Range;

#[derive(Default)]
pub struct CloudTrailContext {
    last_event_num: usize,
    json_value: Option<serde_json::Value>,
    raw_event_data: Vec<u8>,
}

impl CloudTrailPlugin {
    fn ensure_json<'a>(
        context: &'a mut CloudTrailContext,
        event: &EventInput<'_, Event<PluginEvent<&'_ [u8]>>>,
    ) -> Result<&'a serde_json::Value, Error> {
        let event_num = event.event_number();
        if event_num != context.last_event_num || context.json_value.is_none() {
            let evt = event.event()?;
            context.raw_event_data = evt.params.event_data.to_vec();
            // Trim trailing null bytes
            while context.raw_event_data.last() == Some(&0) {
                context.raw_event_data.pop();
            }
            context.json_value = Some(serde_json::from_slice(&context.raw_event_data)?);
            context.last_event_num = event_num;
        }
        context
            .json_value
            .as_ref()
            .ok_or_else(|| anyhow!("No JSON value parsed"))
    }

    /// Extract a string value at a JSON pointer path.
    fn do_extract_string(
        context: &mut CloudTrailContext,
        event: &EventInput<'_, Event<PluginEvent<&'_ [u8]>>>,
        path: &str,
    ) -> Result<Option<Spanned<CString>>, Error> {
        let _ = Self::ensure_json(context, event);
        let value = context
            .json_value
            .as_ref()
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

    /// Extract any JSON value at a path, serializing non-strings to JSON.
    fn do_extract_value(
        context: &mut CloudTrailContext,
        event: &EventInput<'_, Event<PluginEvent<&'_ [u8]>>>,
        path: &str,
    ) -> Result<Option<Spanned<CString>>, Error> {
        let _ = Self::ensure_json(context, event);
        let value = context.json_value.as_ref().and_then(|json| {
            let val = json.pointer(path)?;
            let s = if let Some(s) = val.as_str() {
                s.to_string()
            } else {
                serde_json::to_string(val).ok()?
            };
            Some(s)
        });
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

    // -----------------------------------------------------------------------
    // ct.* fields
    // -----------------------------------------------------------------------

    fn extract_id(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/eventID"),
            req.offset,
        )
    }

    fn extract_error(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/errorCode"),
            req.offset,
        )
    }

    fn extract_errormessage(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/errorMessage"),
            req.offset,
        )
    }

    fn extract_time(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/eventTime"),
            req.offset,
        )
    }

    fn extract_src(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/eventSource"),
            req.offset,
        )
    }

    fn extract_shortsrc(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;

        let result = Self::do_extract_string(context, event, "/eventSource")?;
        match result {
            Some(spanned) => {
                let src = spanned.get_ref().to_str().map_err(|e| anyhow!("{}", e))?;
                let suffix = ".amazonaws.com";
                let trimmed = if src.ends_with(suffix) {
                    &src[..src.len() - suffix.len()]
                } else {
                    src
                };
                if matches!(*offset, ExtractByteRange::Requested) {
                    let span = spanned.span();
                    if !span.is_empty() {
                        *offset = ExtractByteRange::in_plugin_data(span);
                    }
                }
                Ok(Some(CString::new(trimmed)?))
            }
            None => Ok(None),
        }
    }

    fn extract_name(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/eventName"),
            req.offset,
        )
    }

    fn extract_user(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        let utype = match json.pointer("/userIdentity/type").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => return Ok(None),
        };

        let username = match utype.as_str() {
            "Root" | "IAMUser" => json
                .pointer("/userIdentity/userName")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            "AWSService" => json
                .pointer("/userIdentity/invokedBy")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            "AssumedRole" => {
                let v = json
                    .pointer("/userIdentity/sessionContext/sessionIssuer/userName")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if v.is_none() {
                    Some("AssumedRole".to_string())
                } else {
                    v
                }
            }
            "AWSAccount" => Some("AWSAccount".to_string()),
            "FederatedUser" => Some("FederatedUser".to_string()),
            _ => return Ok(None),
        };

        match username {
            Some(name) => Ok(Some(CString::new(name)?)),
            None => Ok(Some(CString::new("<NA>")?)),
        }
    }

    fn extract_originaluser(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        let utype = json
            .pointer("/userIdentity/type")
            .and_then(|v| v.as_str());

        if utype == Some("AssumedRole") {
            // Try ARN: split by '/', if 3 parts return last
            if let Some(arn) = json
                .pointer("/userIdentity/arn")
                .and_then(|v| v.as_str())
            {
                let parts: Vec<&str> = arn.split('/').collect();
                if parts.len() == 3 {
                    return Ok(Some(CString::new(parts[2])?));
                }
            }

            // Try principalId: split by ':', if 2 parts return second
            if let Some(principal) = json
                .pointer("/userIdentity/principalId")
                .and_then(|v| v.as_str())
            {
                let parts: Vec<&str> = principal.split(':').collect();
                if parts.len() == 2 {
                    return Ok(Some(CString::new(parts[1])?));
                }
            }

            return Ok(None);
        }

        // For all other identity types, return userIdentity.userName
        Self::finish_extract(
            Self::do_extract_string(context, event, "/userIdentity/userName"),
            req.offset,
        )
    }

    fn extract_user_accountid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;

        let result = Self::do_extract_string(context, event, "/userIdentity/accountId")?;
        if result.is_some() {
            return Self::finish_extract(Ok(result), offset);
        }
        Self::finish_extract(
            Self::do_extract_string(context, event, "/recipientAccountId"),
            offset,
        )
    }

    fn extract_user_identitytype(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/userIdentity/type"),
            req.offset,
        )
    }

    fn extract_user_principalid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/userIdentity/principalId"),
            req.offset,
        )
    }

    fn extract_user_arn(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/userIdentity/arn"),
            req.offset,
        )
    }

    fn extract_region(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/awsRegion"),
            req.offset,
        )
    }

    fn extract_response_subnetid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/responseElements/subnetId"),
            req.offset,
        )
    }

    fn extract_response_reservationid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/responseElements/reservationId",
            ),
            req.offset,
        )
    }

    fn extract_response(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_value(req.context, req.event, "/responseElements"),
            req.offset,
        )
    }

    fn extract_request_availabilityzone(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/availabilityZone",
            ),
            req.offset,
        )
    }

    fn extract_request_cluster(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/cluster"),
            req.offset,
        )
    }

    fn extract_request_functionname(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/functionName",
            ),
            req.offset,
        )
    }

    fn extract_request_groupname(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/groupName"),
            req.offset,
        )
    }

    fn extract_request_host(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/Host"),
            req.offset,
        )
    }

    fn extract_request_name(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/name"),
            req.offset,
        )
    }

    fn extract_request_policy(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/policy"),
            req.offset,
        )
    }

    fn extract_request_reason(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/reason"),
            req.offset,
        )
    }

    fn extract_request_target(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/target"),
            req.offset,
        )
    }

    fn extract_request_documentname(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/documentName",
            ),
            req.offset,
        )
    }

    fn extract_request_serialnumber(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/serialNumber",
            ),
            req.offset,
        )
    }

    fn extract_request_servicename(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/serviceName",
            ),
            req.offset,
        )
    }

    fn extract_request_subnetid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/subnetId"),
            req.offset,
        )
    }

    fn extract_request_taskdefinition(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/taskDefinition",
            ),
            req.offset,
        )
    }

    fn extract_request_username(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/userName"),
            req.offset,
        )
    }

    fn extract_request(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_value(req.context, req.event, "/requestParameters"),
            req.offset,
        )
    }

    fn extract_srcip(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/sourceIPAddress"),
            req.offset,
        )
    }

    fn extract_useragent(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/userAgent"),
            req.offset,
        )
    }

    fn extract_info(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        // Get user
        let user = get_user_string(json);

        // Get source IP
        let srcip = json
            .pointer("/sourceIPAddress")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Get event name
        let evtname = match json.pointer("/eventName").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => {
                return Ok(Some(CString::new(
                    "<invalid cloudtrail event: eventName field missing>",
                )?));
            }
        };

        // Error symbol
        let err_symbol = if json.get("errorCode").is_some() {
            "!"
        } else {
            ""
        };

        // Read/write symbol
        let readonly = json
            .pointer("/readOnly")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let rw_symbol = if readonly { "←" } else { "→" };

        // Build info string
        let base = if user == srcip {
            format!("{} {}{} {}", user, err_symbol, rw_symbol, evtname)
        } else {
            format!(
                "{} via {} {}{} {}",
                user, srcip, err_symbol, rw_symbol, evtname
            )
        };

        // Add s3 info if available
        let mut info = base;

        // Check for s3 bytes
        let bytes_in = json
            .pointer("/additionalEventData/bytesTransferredIn")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0) as u64;
        let bytes_out = json
            .pointer("/additionalEventData/bytesTransferredOut")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0) as u64;
        let total_bytes = bytes_in + bytes_out;
        if total_bytes > 0 {
            info.push_str(&format!(" Size={}", total_bytes));
        }

        // Check for s3 URI
        if let (Some(bucket), Some(key)) = (
            json.pointer("/requestParameters/bucketName")
                .and_then(|v| v.as_str()),
            json.pointer("/requestParameters/key")
                .and_then(|v| v.as_str()),
        ) {
            info.push_str(&format!(" URI=s3://{}/{}", bucket, key));
            return Ok(Some(CString::new(info)?));
        }

        if let Some(bucket) = json
            .pointer("/requestParameters/bucketName")
            .and_then(|v| v.as_str())
        {
            info.push_str(&format!(" Bucket={}", bucket));
            return Ok(Some(CString::new(info)?));
        }

        if let Some(key) = json
            .pointer("/requestParameters/key")
            .and_then(|v| v.as_str())
        {
            info.push_str(&format!(" Key={}", key));
            return Ok(Some(CString::new(info)?));
        }

        if let Some(host) = json
            .pointer("/requestParameters/Host")
            .and_then(|v| v.as_str())
        {
            info.push_str(&format!(" Host={}", host));
            return Ok(Some(CString::new(info)?));
        }

        Ok(Some(CString::new(info)?))
    }

    fn extract_managementevent(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;
        let _ = Self::ensure_json(context, event);

        let val = context
            .json_value
            .as_ref()
            .and_then(|json| json.get("managementEvent"))
            .and_then(|v| v.as_bool());

        match val {
            Some(b) => {
                let span =
                    find_json_pointer_range(&context.raw_event_data, "/managementEvent")
                        .unwrap_or(0..0);
                if matches!(*offset, ExtractByteRange::Requested) && !span.is_empty() {
                    *offset = ExtractByteRange::in_plugin_data(span);
                }
                let s = if b { "true" } else { "false" };
                Ok(Some(CString::new(s)?))
            }
            None => Ok(None),
        }
    }

    fn extract_readonly(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        let ro_val = json.get("readOnly");

        if ro_val.is_none() {
            // Heuristic based on event name prefix
            let evtname = json
                .pointer("/eventName")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let write_prefixes = [
                "Start",
                "Stop",
                "Create",
                "Destroy",
                "Delete",
                "Add",
                "Remove",
                "Terminate",
                "Put",
                "Associate",
                "Disassociate",
                "Attach",
                "Detach",
                "Open",
                "Close",
                "Wipe",
                "Update",
                "Upgrade",
                "Unlink",
                "Assign",
                "Unassign",
                "Suspend",
                "Set",
                "Run",
                "Register",
                "Deregister",
                "Reboot",
                "Purchase",
                "Modify",
                "Initialize",
                "Enable",
                "Disable",
                "Cancel",
                "Admin",
                "Activate",
            ];

            let is_write = write_prefixes
                .iter()
                .any(|prefix| evtname.starts_with(prefix));
            let s = if is_write { "false" } else { "true" };
            return Ok(Some(CString::new(s)?));
        }

        let ro = ro_val.unwrap().as_bool().unwrap_or(false);
        let span = find_json_pointer_range(&context.raw_event_data, "/readOnly")
            .unwrap_or(0..0);
        if matches!(*offset, ExtractByteRange::Requested) && !span.is_empty() {
            *offset = ExtractByteRange::in_plugin_data(span);
        }
        let s = if ro { "true" } else { "false" };
        Ok(Some(CString::new(s)?))
    }

    fn extract_requestid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestID"),
            req.offset,
        )
    }

    fn extract_eventtype(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/eventType"),
            req.offset,
        )
    }

    fn extract_apiversion(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/apiVersion"),
            req.offset,
        )
    }

    fn extract_resources(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;
        let _ = Self::ensure_json(context, event);

        let arr = context
            .json_value
            .as_ref()
            .and_then(|json| json.get("resources"))
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty());

        match arr {
            Some(resources) => {
                let joined: String = resources
                    .iter()
                    .map(|r| serde_json::to_string(r).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(",");
                if joined.is_empty() {
                    return Ok(None);
                }
                let span =
                    find_json_pointer_range(&context.raw_event_data, "/resources")
                        .unwrap_or(0..0);
                if matches!(*offset, ExtractByteRange::Requested) && !span.is_empty() {
                    *offset = ExtractByteRange::in_plugin_data(span);
                }
                Ok(Some(CString::new(joined)?))
            }
            None => Ok(None),
        }
    }

    fn extract_recipientaccountid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/recipientAccountId"),
            req.offset,
        )
    }

    fn extract_serviceeventdetails(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_value(req.context, req.event, "/serviceEventDetails"),
            req.offset,
        )
    }

    fn extract_sharedeventid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/sharedEventID"),
            req.offset,
        )
    }

    fn extract_vpcendpointid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/vpcEndpointId"),
            req.offset,
        )
    }

    fn extract_eventcategory(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/eventCategory"),
            req.offset,
        )
    }

    fn extract_addendum_reason(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/addendum/reason"),
            req.offset,
        )
    }

    fn extract_addendum_updatedfields(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/addendum/updatedFields"),
            req.offset,
        )
    }

    fn extract_addendum_originalrequestid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/addendum/originalRequestID"),
            req.offset,
        )
    }

    fn extract_addendum_originaleventid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/addendum/originalEventID"),
            req.offset,
        )
    }

    fn extract_sessioncredentialfromconsole(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let offset = req.offset;
        let _ = Self::ensure_json(context, event);

        let val = context
            .json_value
            .as_ref()
            .and_then(|json| json.get("sessionCredentialFromConsole"))
            .and_then(|v| v.as_bool());

        match val {
            Some(b) => {
                let span = find_json_pointer_range(
                    &context.raw_event_data,
                    "/sessionCredentialFromConsole",
                )
                .unwrap_or(0..0);
                if matches!(*offset, ExtractByteRange::Requested) && !span.is_empty() {
                    *offset = ExtractByteRange::in_plugin_data(span);
                }
                let s = if b { "true" } else { "false" };
                Ok(Some(CString::new(s)?))
            }
            None => Ok(None),
        }
    }

    fn extract_edgedevicedetails(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_value(req.context, req.event, "/edgeDeviceDetails"),
            req.offset,
        )
    }

    fn extract_tlsdetails_tlsversion(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/tlsDetails/tlsVersion"),
            req.offset,
        )
    }

    fn extract_tlsdetails_ciphersuite(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/tlsDetails/cipherSuite"),
            req.offset,
        )
    }

    fn extract_tlsdetails_clientprovidedhostheader(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/tlsDetails/clientProvidedHostHeader",
            ),
            req.offset,
        )
    }

    fn extract_additionaleventdata(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_value(req.context, req.event, "/additionalEventData"),
            req.offset,
        )
    }

    // -----------------------------------------------------------------------
    // s3.* fields
    // -----------------------------------------------------------------------

    fn extract_s3_uri(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        let bucket = json
            .pointer("/requestParameters/bucketName")
            .and_then(|v| v.as_str());
        let key = json
            .pointer("/requestParameters/key")
            .and_then(|v| v.as_str());

        match (bucket, key) {
            (Some(b), Some(k)) => Ok(Some(CString::new(format!("s3://{}/{}", b, k))?)),
            _ => Ok(None),
        }
    }

    fn extract_s3_bucket(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/bucketName"),
            req.offset,
        )
    }

    fn extract_s3_key(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/key"),
            req.offset,
        )
    }

    fn extract_s3_bytes(&mut self, req: ExtractRequest<Self>) -> Result<Option<u64>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        let bytes_in = json
            .pointer("/additionalEventData/bytesTransferredIn")
            .and_then(get_value_u64);
        let bytes_out = json
            .pointer("/additionalEventData/bytesTransferredOut")
            .and_then(get_value_u64);

        if bytes_in.is_none() && bytes_out.is_none() {
            return Ok(None);
        }

        Ok(Some(bytes_in.unwrap_or(0) + bytes_out.unwrap_or(0)))
    }

    fn extract_s3_bytes_in(&mut self, req: ExtractRequest<Self>) -> Result<Option<u64>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        Ok(context
            .json_value
            .as_ref()
            .and_then(|json| json.pointer("/additionalEventData/bytesTransferredIn"))
            .and_then(get_value_u64))
    }

    fn extract_s3_bytes_out(&mut self, req: ExtractRequest<Self>) -> Result<Option<u64>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        Ok(context
            .json_value
            .as_ref()
            .and_then(|json| json.pointer("/additionalEventData/bytesTransferredOut"))
            .and_then(get_value_u64))
    }

    fn extract_s3_cnt_get(&mut self, req: ExtractRequest<Self>) -> Result<Option<u64>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let is_get = context
            .json_value
            .as_ref()
            .and_then(|json| json.pointer("/eventName"))
            .and_then(|v| v.as_str())
            == Some("GetObject");

        if is_get {
            Ok(Some(1))
        } else {
            Ok(None)
        }
    }

    fn extract_s3_cnt_put(&mut self, req: ExtractRequest<Self>) -> Result<Option<u64>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let is_put = context
            .json_value
            .as_ref()
            .and_then(|json| json.pointer("/eventName"))
            .and_then(|v| v.as_str())
            == Some("PutObject");

        if is_put {
            Ok(Some(1))
        } else {
            Ok(None)
        }
    }

    fn extract_s3_cnt_other(&mut self, req: ExtractRequest<Self>) -> Result<Option<u64>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let evtname = context
            .json_value
            .as_ref()
            .and_then(|json| json.pointer("/eventName"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if evtname == "GetObject" || evtname == "PutObject" {
            Ok(None)
        } else {
            Ok(Some(1))
        }
    }

    // -----------------------------------------------------------------------
    // ec2.* fields
    // -----------------------------------------------------------------------

    fn extract_ec2_name(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        let items = json
            .pointer("/requestParameters/tagSpecificationSet/items")
            .and_then(|v| v.as_array());

        let items = match items {
            Some(i) => i,
            None => return Ok(None),
        };

        for item in items {
            let resource_type = item
                .pointer("/resourceType")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if resource_type != "instance" {
                continue;
            }
            if let Some(tags) = item.get("tags").and_then(|v| v.as_array()) {
                for tag in tags {
                    let key = tag.get("key").and_then(|v| v.as_str()).unwrap_or("");
                    if key == "Name" {
                        if let Some(value) = tag.get("value").and_then(|v| v.as_str()) {
                            if !value.is_empty() {
                                return Ok(Some(CString::new(value)?));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn extract_ec2_imageid(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        let context = req.context;
        let event = req.event;
        let _ = Self::ensure_json(context, event);

        let json = match context.json_value.as_ref() {
            Some(j) => j,
            None => return Ok(None),
        };

        let items = json
            .pointer("/responseElements/tagSpecificationSet/items")
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty());

        match items {
            Some(items) => {
                let image_id = items[0]
                    .get("imageId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if image_id.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(CString::new(image_id)?))
                }
            }
            None => Ok(None),
        }
    }

    // -----------------------------------------------------------------------
    // ecr.* fields
    // -----------------------------------------------------------------------

    fn extract_ecr_repository(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/repositoryName",
            ),
            req.offset,
        )
    }

    fn extract_ecr_imagetag(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/imageTag"),
            req.offset,
        )
    }

    // -----------------------------------------------------------------------
    // iam.* fields
    // -----------------------------------------------------------------------

    fn extract_iam_role(&mut self, req: ExtractRequest<Self>) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(req.context, req.event, "/requestParameters/roleName"),
            req.offset,
        )
    }

    fn extract_iam_policy(
        &mut self,
        req: ExtractRequest<Self>,
    ) -> Result<Option<CString>, Error> {
        Self::finish_extract(
            Self::do_extract_string(
                req.context,
                req.event,
                "/requestParameters/policyName",
            ),
            req.offset,
        )
    }
}

impl ExtractPlugin for CloudTrailPlugin {
    type Event<'a> = Event<PluginEvent<&'a [u8]>>;
    type ExtractContext = CloudTrailContext;
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        // ct.* fields
        field("ct.id", &Self::extract_id)
            .with_display("Event ID")
            .with_description("the unique ID of the cloudtrail event (eventID in the json)."),
        field("ct.error", &Self::extract_error)
            .with_display("Error Code")
            .with_description("The error code from the event. Will be \"<NA>\" (e.g. the NULL/empty/none value) if there was no error."),
        field("ct.errormessage", &Self::extract_errormessage)
            .with_display("Error Message")
            .with_description("The description of an error. Will be \"<NA>\" (e.g. the NULL/empty/none value) if there was no error."),
        field("ct.time", &Self::extract_time)
            .with_display("Timestamp")
            .with_description("the timestamp of the cloudtrail event (eventTime in the json)."),
        field("ct.src", &Self::extract_src)
            .with_display("AWS Service")
            .with_description("the source of the cloudtrail event (eventSource in the json)."),
        field("ct.shortsrc", &Self::extract_shortsrc)
            .with_display("AWS Service")
            .with_description("the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer)."),
        field("ct.name", &Self::extract_name)
            .with_display("Event Name")
            .with_description("the name of the cloudtrail event (eventName in the json)."),
        field("ct.user", &Self::extract_user)
            .with_display("User Name")
            .with_description("the user of the cloudtrail event (userIdentity.userName in the json). For AssumedRole events, this is the role name from sessionContext.sessionIssuer.userName."),
        field("ct.originaluser", &Self::extract_originaluser)
            .with_display("Original User Name")
            .with_description("the user name as seen in CloudTrail. For AssumedRole events, this is the session name extracted from userIdentity.arn or userIdentity.principalId. For all other identity types, this is userIdentity.userName."),
        field("ct.user.accountid", &Self::extract_user_accountid)
            .with_display("User Account ID")
            .with_description("the account id of the user of the cloudtrail event."),
        field("ct.user.identitytype", &Self::extract_user_identitytype)
            .with_display("User Identity Type")
            .with_description("the kind of user identity (e.g. Root, IAMUser,AWSService, etc.)"),
        field("ct.user.principalid", &Self::extract_user_principalid)
            .with_display("User Principal Id")
            .with_description("A unique identifier for the user that made the request."),
        field("ct.user.arn", &Self::extract_user_arn)
            .with_display("User ARN")
            .with_description("the Amazon Resource Name (ARN) of the user that made the request."),
        field("ct.region", &Self::extract_region)
            .with_display("Region")
            .with_description("the region of the cloudtrail event (awsRegion in the json)."),
        field("ct.response.subnetid", &Self::extract_response_subnetid)
            .with_display("Response Subnet ID")
            .with_description("the subnet ID included in the response."),
        field("ct.response.reservationid", &Self::extract_response_reservationid)
            .with_display("Response Reservation ID")
            .with_description("the reservation ID included in the response."),
        field("ct.response", &Self::extract_response)
            .with_display("Response Elements")
            .with_description("All response elements."),
        field("ct.request.availabilityzone", &Self::extract_request_availabilityzone)
            .with_display("Request Availability Zone")
            .with_description("the availability zone included in the request."),
        field("ct.request.cluster", &Self::extract_request_cluster)
            .with_display("Request Cluster")
            .with_description("the cluster included in the request."),
        field("ct.request.functionname", &Self::extract_request_functionname)
            .with_display("Request Function Name")
            .with_description("the function name included in the request."),
        field("ct.request.groupname", &Self::extract_request_groupname)
            .with_display("Request Group Name")
            .with_description("the group name included in the request."),
        field("ct.request.host", &Self::extract_request_host)
            .with_display("Request Host Name")
            .with_description("the host included in the request"),
        field("ct.request.name", &Self::extract_request_name)
            .with_display("Host Name")
            .with_description("the name of the entity being acted on in the request."),
        field("ct.request.policy", &Self::extract_request_policy)
            .with_display("Host Policy")
            .with_description("the policy included in the request"),
        field("ct.request.reason", &Self::extract_request_reason)
            .with_display("Request Reason")
            .with_description("the reason included in the request."),
        field("ct.request.target", &Self::extract_request_target)
            .with_display("Request Target")
            .with_description("the target included in the request."),
        field("ct.request.documentname", &Self::extract_request_documentname)
            .with_display("Request Document Name")
            .with_description("the document name included in the request."),
        field("ct.request.serialnumber", &Self::extract_request_serialnumber)
            .with_display("Request Serial Number")
            .with_description("the serial number provided in the request."),
        field("ct.request.servicename", &Self::extract_request_servicename)
            .with_display("Request Service")
            .with_description("the service name provided in the request."),
        field("ct.request.subnetid", &Self::extract_request_subnetid)
            .with_display("Request Subnet ID")
            .with_description("the subnet ID provided in the request."),
        field("ct.request.taskdefinition", &Self::extract_request_taskdefinition)
            .with_display("Request Task Definition")
            .with_description("the task definition provided in the request."),
        field("ct.request.username", &Self::extract_request_username)
            .with_display("Request User Name")
            .with_description("the username provided in the request."),
        field("ct.request", &Self::extract_request)
            .with_display("Request Parameters")
            .with_description("All request parameters."),
        field("ct.srcip", &Self::extract_srcip)
            .with_display("Source IP")
            .with_description("the IP address generating the event (sourceIPAddress in the json)."),
        field("ct.useragent", &Self::extract_useragent)
            .with_display("User Agent")
            .with_description("the user agent generating the event (userAgent in the json)."),
        field("ct.info", &Self::extract_info)
            .with_display("Info")
            .with_description("summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details."),
        field("ct.managementevent", &Self::extract_managementevent)
            .with_display("Management Event")
            .with_description("'true' if the event is a management event (AwsApiCall, AwsConsoleAction, AwsConsoleSignIn, or AwsServiceEvent), 'false' otherwise."),
        field("ct.readonly", &Self::extract_readonly)
            .with_display("Read Only")
            .with_description("'true' if the event only reads information (e.g. DescribeInstances), 'false' if the event modifies the state (e.g. RunInstances, CreateLoadBalancer...)."),
        field("ct.requestid", &Self::extract_requestid)
            .with_display("Request ID")
            .with_description("The value that identifies the request."),
        field("ct.eventtype", &Self::extract_eventtype)
            .with_display("Event Type")
            .with_description("Identifies the type of event that generated the event record."),
        field("ct.apiversion", &Self::extract_apiversion)
            .with_display("API Version")
            .with_description("The API version associated with the AwsApiCall eventType value."),
        field("ct.resources", &Self::extract_resources)
            .with_display("Resources")
            .with_description("A list of resources accessed in the event."),
        field("ct.recipientaccountid", &Self::extract_recipientaccountid)
            .with_display("Recipient Account Id")
            .with_description("The account ID that received this event."),
        field("ct.serviceeventdetails", &Self::extract_serviceeventdetails)
            .with_display("Service Event Details")
            .with_description("Identifies the service event, including what triggered the event and the result."),
        field("ct.sharedeventid", &Self::extract_sharedeventid)
            .with_display("Shared Event ID")
            .with_description("GUID generated by CloudTrail to uniquely identify CloudTrail events."),
        field("ct.vpcendpointid", &Self::extract_vpcendpointid)
            .with_display("VPC Endpoint ID")
            .with_description("Identifies the VPC endpoint in which requests were made."),
        field("ct.eventcategory", &Self::extract_eventcategory)
            .with_display("Event Category")
            .with_description("Shows the event category that is used in LookupEvents calls."),
        field("ct.addendum.reason", &Self::extract_addendum_reason)
            .with_display("Reason")
            .with_description("The reason that the event or some of its contents were missing."),
        field("ct.addendum.updatedfields", &Self::extract_addendum_updatedfields)
            .with_display("Updated Fields")
            .with_description("The event record fields that are updated by the addendum."),
        field("ct.addendum.originalrequestid", &Self::extract_addendum_originalrequestid)
            .with_display("Original Request ID")
            .with_description("The original unique ID of the request."),
        field("ct.addendum.originaleventid", &Self::extract_addendum_originaleventid)
            .with_display("Original Event ID")
            .with_description("The original event ID."),
        field("ct.sessioncredentialfromconsole", &Self::extract_sessioncredentialfromconsole)
            .with_display("Session Credential From Console")
            .with_description("Shows whether or not an event originated from an AWS Management Console session."),
        field("ct.edgedevicedetails", &Self::extract_edgedevicedetails)
            .with_display("Edge Device Details")
            .with_description("Information about edge devices that are targets of a request."),
        field("ct.tlsdetails.tlsversion", &Self::extract_tlsdetails_tlsversion)
            .with_display("TLS Version")
            .with_description("The TLS version of a request."),
        field("ct.tlsdetails.ciphersuite", &Self::extract_tlsdetails_ciphersuite)
            .with_display("TLS Cipher Suite")
            .with_description("The cipher suite (combination of security algorithms used) of a request."),
        field("ct.tlsdetails.clientprovidedhostheader", &Self::extract_tlsdetails_clientprovidedhostheader)
            .with_display("Client Provided Host Header")
            .with_description("The client-provided host name used in the service API call."),
        field("ct.additionaleventdata", &Self::extract_additionaleventdata)
            .with_display("Additional Event Data")
            .with_description("All additional event data attributes."),
        // s3.* fields
        field("s3.uri", &Self::extract_s3_uri)
            .with_display("Key URI")
            .with_description("the s3 URI (s3://<bucket>/<key>)."),
        field("s3.bucket", &Self::extract_s3_bucket)
            .with_display("Bucket Name")
            .with_description("the bucket name for s3 events."),
        field("s3.key", &Self::extract_s3_key)
            .with_display("Key Name")
            .with_description("the S3 key name."),
        field("s3.bytes", &Self::extract_s3_bytes)
            .with_display("Total Bytes")
            .with_description("the size of an s3 download or upload, in bytes."),
        field("s3.bytes.in", &Self::extract_s3_bytes_in)
            .with_display("Bytes In")
            .with_description("the size of an s3 upload, in bytes."),
        field("s3.bytes.out", &Self::extract_s3_bytes_out)
            .with_display("Bytes Out")
            .with_description("the size of an s3 download, in bytes."),
        field("s3.cnt.get", &Self::extract_s3_cnt_get)
            .with_display("N Get Ops")
            .with_description("the number of get operations. This field is 1 for GetObject events, 0 otherwise."),
        field("s3.cnt.put", &Self::extract_s3_cnt_put)
            .with_display("N Put Ops")
            .with_description("the number of put operations. This field is 1 for PutObject events, 0 otherwise."),
        field("s3.cnt.other", &Self::extract_s3_cnt_other)
            .with_display("N Other Ops")
            .with_description("the number of non I/O operations. This field is 0 for GetObject and PutObject events, 1 for all the other events."),
        // ec2.* fields
        field("ec2.name", &Self::extract_ec2_name)
            .with_display("Instance Name")
            .with_description("the name of the ec2 instances, typically stored in the instance tags."),
        field("ec2.imageid", &Self::extract_ec2_imageid)
            .with_display("Image Id")
            .with_description("the ID for the image used to run the ec2 instance in the response."),
        // ecr.* fields
        field("ecr.repository", &Self::extract_ecr_repository)
            .with_display("ECR Repository name")
            .with_description("the name of the ecr Repository specified in the request."),
        field("ecr.imagetag", &Self::extract_ecr_imagetag)
            .with_display("Image Tag")
            .with_description("the tag of the image specified in the request."),
        // iam.* fields
        field("iam.role", &Self::extract_iam_role)
            .with_display("IAM Role")
            .with_description("the IAM role specified in the request."),
        field("iam.policy", &Self::extract_iam_policy)
            .with_display("IAM Policy")
            .with_description("the IAM policy specified in the request."),
    ];
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Extract user string from CloudTrail JSON for the ct.info field
fn get_user_string(json: &serde_json::Value) -> String {
    let utype = match json.pointer("/userIdentity/type").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return String::new(),
    };

    match utype {
        "Root" | "IAMUser" => json
            .pointer("/userIdentity/userName")
            .and_then(|v| v.as_str())
            .unwrap_or("<NA>")
            .to_string(),
        "AWSService" => json
            .pointer("/userIdentity/invokedBy")
            .and_then(|v| v.as_str())
            .unwrap_or("<NA>")
            .to_string(),
        "AssumedRole" => json
            .pointer("/userIdentity/sessionContext/sessionIssuer/userName")
            .and_then(|v| v.as_str())
            .unwrap_or("AssumedRole")
            .to_string(),
        "AWSAccount" => "AWSAccount".to_string(),
        "FederatedUser" => "FederatedUser".to_string(),
        _ => "<NA>".to_string(),
    }
}

/// Extract a numeric value from a JSON value, handling both int and float representations.
fn get_value_u64(value: &serde_json::Value) -> Option<u64> {
    if let Some(u) = value.as_u64() {
        return Some(u);
    }
    if let Some(f) = value.as_f64() {
        return Some(f as u64);
    }
    None
}

// ---------------------------------------------------------------------------
// JSON byte-offset helpers (from gcpaudit-rs)
// ---------------------------------------------------------------------------

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
