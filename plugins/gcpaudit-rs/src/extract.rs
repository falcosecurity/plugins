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

use falco_plugin::anyhow::{anyhow, Error};
use falco_event::events::RawEvent;
use falco_plugin::extract::{
    field, EventInput, ExtractFieldInfo, ExtractPlugin, ExtractRequest,
};
use serde_json::Value;
use std::ffi::{CString};

// use crate::GcpAuditPlugin;

struct GcpAuditContext {
    last_event_num: usize,
    json_value: Option<serde_json::Value>,
}

impl GcpAuditPlugin {
    pub const FIELD_NAMES: &'static [&'static str] = &[
        // "gcp.user",
        "gcp.callerIP",
        "gcp.userAgent",
        "gcp.authorizationInfo",
        "gcp.serviceName",
        "gcp.policyDelta",
        "gcp.request",
        "gcp.methodName",
        "gcp.cloudfunctions.function",
        "gcp.cloudsql.databaseId",
        "gcp.compute.instanceId",
        "gcp.compute.networkId",
        "gcp.compute.subnetwork",
        "gcp.compute.subnetworkId",
        "gcp.dns.zone",
        "gcp.iam.serviceAccount",
        "gcp.iam.serviceAccountId",
        "gcp.location",
        "gcp.logging.sink",
        "gcp.projectId",
        "gcp.resourceName",
        "gcp.resourceType",
        "gcp.resourceLabels",
        "gcp.storage.bucket",
        "gcp.time",
    ];

    fn parse_event<'a>(&self, context: &'a GcpAuditContext, event: &EventInput<RawEvent<'a>>) -> Result<&serde_json::Value, Error> {
        if event.event_number() != context.last_event_num {
            let raw_event = event.event()?;
            context.json_value = Some(serde_json::from_slice::<serde_json::Value>(raw_event.payload)?);
            context.last_event_num = event.event_number();
        }
        context.json_value.as_ref().ok_or_else(|| anyhow!("No JSON value parsed"))
    }

    fn extract_string<'a>(&self, context: &'a GcpAuditContext, event: &EventInput<RawEvent<'a>>, path: &str) -> Result<CString, Error> {
        let json = self.parse_event(context, event)?;
        let value = json.pointer(path).and_then(|v: &Value| v.as_str()).ok_or_else(|| anyhow!("Field not found at path: {}", path))?;
        Ok(CString::new(value)?)
    }

    fn del_extract_string(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let json = self.parse_event(req)?;
        let field_str = req.field_name();

        let value = match field_str {
            "gcp.userAgent" => json
                .pointer("/protoPayload/requestMetadata/callerSuppliedUserAgent")
                .and_then(|v| v.as_str()),

            "gcp.authorizationInfo" => json
                .pointer("/protoPayload/authorizationInfo")
                .map(|v| v.to_string())
                .as_deref(),

            "gcp.serviceName" => json
                .pointer("/protoPayload/serviceName")
                .and_then(|v| v.as_str()),

            "gcp.request" => json
                .pointer("/protoPayload/request")
                .map(|v| v.to_string())
                .as_deref(),

            "gcp.policyDelta" => {
                let resource_type = json
                    .pointer("/resource/type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if resource_type == "gcs_bucket" {
                    json.pointer("/protoPayload/serviceData/policyDelta/bindingDeltas")
                        .map(|v| v.to_string())
                        .as_deref()
                } else {
                    json.pointer("/protoPayload/metadata/datasetChange/bindingDeltas")
                        .map(|v| v.to_string())
                        .as_deref()
                }
            }

            "gcp.methodName" => json
                .pointer("/protoPayload/methodName")
                .and_then(|v| v.as_str()),

            "gcp.cloudfunctions.function" => json
                .pointer("/resource/labels/function_name")
                .and_then(|v| v.as_str()),

            "gcp.cloudsql.databaseId" => json
                .pointer("/resource/labels/database_id")
                .and_then(|v| v.as_str()),

            "gcp.compute.instanceId" => json
                .pointer("/resource/labels/instance_id")
                .and_then(|v| v.as_str()),

            "gcp.compute.networkId" => json
                .pointer("/resource/labels/network_id")
                .and_then(|v| v.as_str()),

            "gcp.compute.subnetwork" => json
                .pointer("/resource/labels/subnetwork_name")
                .and_then(|v| v.as_str()),

            "gcp.compute.subnetworkId" => json
                .pointer("/resource/labels/subnetwork_id")
                .and_then(|v| v.as_str()),

            "gcp.dns.zone" => json
                .pointer("/resource/labels/zone_name")
                .and_then(|v| v.as_str()),

            "gcp.iam.serviceAccount" => json
                .pointer("/resource/labels/email_id")
                .and_then(|v| v.as_str()),

            "gcp.iam.serviceAccountId" => json
                .pointer("/resource/labels/unique_id")
                .and_then(|v| v.as_str()),

            "gcp.location" => {
                // Try location first
                if let Some(val) = json.pointer("/resource/labels/location").and_then(|v| v.as_str()) {
                    Some(val)
                } else if let Some(val) = json.pointer("/resource/labels/region").and_then(|v| v.as_str()) {
                    // Try region
                    Some(val)
                } else if let Some(zone) = json.pointer("/resource/labels/zone").and_then(|v| v.as_str()) {
                    // Try zone and format it
                    if zone.len() > 2 {
                        // Remove last two chars for zone format like "us-central1-a"
                        Some(&zone[..zone.len() - 2])
                    } else if !zone.is_empty() {
                        Some(zone)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }

            "gcp.logging.sink" => {
                let resource_type = json
                    .pointer("/resource/type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if resource_type == "logging_sink" {
                    json.pointer("/resource/labels/name").and_then(|v| v.as_str())
                } else {
                    None
                }
            }

            "gcp.projectId" => json
                .pointer("/resource/labels/project_id")
                .and_then(|v| v.as_str()),

            "gcp.resourceName" => json
                .pointer("/protoPayload/resourceName")
                .and_then(|v| v.as_str()),

            "gcp.resourceType" => json
                .pointer("/resource/type")
                .and_then(|v| v.as_str()),

            "gcp.resourceLabels" => json
                .pointer("/resource/labels")
                .map(|v| v.to_string())
                .as_deref(),

            "gcp.storage.bucket" => json
                .pointer("/resource/labels/bucket_name")
                .and_then(|v| v.as_str()),

            "gcp.time" => json
                .pointer("/timestamp")
                .and_then(|v| v.as_str()),

            _ => return Err(anyhow!("Unknown field: {}", field_str)),
        };

        Ok(value.map(|s| s.to_string()))
    }

    fn extract_user(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let user = self.extract_string(req, "/protoPayload/authenticationInfo/principalEmail")?;
        Ok(user)
    }

    fn extract_caller_ip(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let caller_ip = self.extract_string(req, "/protoPayload/requestMetadata/callerIp")?;
        Ok(caller_ip)
    }

    fn extract_user_agent(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let user_agent = self.extract_string(req, "/protoPayload/requestMetadata/callerSuppliedUserAgent")?;
        Ok(user_agent)
    }

    fn extract_authorization_info(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let auth_info = self.extract_string(req, "/protoPayload/authorizationInfo")?;
        Ok(auth_info)
    }

    fn extract_service_name(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let service_name = self.extract_string(req, "/protoPayload/serviceName")?;
        Ok(service_name)
    }

    fn extract_policy_delta(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let resource_type = self.extract_string(req, "/resource/type")?.to_str()?;

        let path = if resource_type == "gcs_bucket" {
            "/protoPayload/serviceData/policyDelta/bindingDeltas"
        } else {
            "/protoPayload/metadata/datasetChange/bindingDeltas"
        };

        let policy_delta = self.extract_string(req, path)?;
        Ok(policy_delta)
    }

    fn extract_request(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let request = self.extract_string(req, "/protoPayload/request")?;
        Ok(request)
    }

    fn extract_method_name(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let method_name = self.extract_string(req, "/protoPayload/methodName")?;
        Ok(method_name)
    }

    fn extract_cloudfunctions_function(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let cloud_function = self.extract_string(req, "/resource/labels/function_name")?;
        Ok(cloud_function)
    }

    fn extract_cloudsql_database_id(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let database_id = self.extract_string(req, "/resource/labels/database_id")?;
        Ok(database_id)
    }

    fn extract_compute_instance_id(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let instance_id = self.extract_string(req, "/resource/labels/instance_id")?;
        Ok(instance_id)
    }

    fn extract_compute_network_id(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let network_id = self.extract_string(req, "/resource/labels/network_id")?;
        Ok(network_id)
    }

    fn extract_compute_subnetwork(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let subnetwork = self.extract_string(req, "/resource/labels/subnetwork_name")?;
        Ok(subnetwork)
    }

    fn extract_compute_subnetwork_id(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let subnetwork_id = self.extract_string(req, "/resource/labels/subnetwork_id")?;
        Ok(subnetwork_id)
    }

    fn extract_dns_zone(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let dns_zone = self.extract_string(req, "/resource/labels/zone_name")?;
        Ok(dns_zone)
    }

    fn extract_iam_service_account(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let service_account = self.extract_string(req, "/resource/labels/email_id")?;
        Ok(service_account)
    }

    fn extract_iam_service_account_id(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let service_account_id = self.extract_string(req, "/resource/labels/unique_id")?;
        Ok(service_account_id)
    }

    fn extract_location(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        if let location = self.extract_string(req, "/resource/labels/location") {
            return location
        } else if let region = self.extract_string(req, "/resource/labels/region") {
            // if location is not present, check for region
            return region
        } else if let zone = self.extract_string(req, "/resource/labels/zone") {
            // if region is not present, check for zone
            let zone_str = zone.to_str()?;
            if zone_str.len() > 2 {
                // if in format: "us-central1-a", remove last two chars
                return Ok(CString::new(&zone_str[..zone_str.len() - 2])?)
            } else if !zone_str.is_empty() {
                return zone
            }
        }
        Err(anyhow!("No location, region, or zone found"))
    }

    fn extract_logging_sink(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let resource_type = self.extract_string(req, "/resource/type")?.to_str()?;

        if resource_type == "logging_sink" {
            let logging_sink = self.extract_string(req, "/resource/labels/name")?;
            Ok(logging_sink)
        } else {
            Err(anyhow!("Resource type is not logging_sink"))
        }
    }

    fn extract_project_id(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let project_id = self.extract_string(req, "/resource/labels/project_id")?;
        Ok(project_id)
    }

    fn extract_resource_name(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let resource_name = self.extract_string(req, "/protoPayload/resourceName")?;
        Ok(resource_name)
    }

    fn extract_resource_type(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let resource_type = self.extract_string(req, "/resource/type")?;
        Ok(resource_type)
    }

    fn extract_resource_labels(&mut self, req: ExtractRequest<Self>) -> Result<CString, Error> {
        let resource_labels = self.extract_string(req, "/resource/labels")?;
        Ok(resource_labels)
    }
    
}

impl ExtractPlugin for GcpAuditPlugin {
    type Event<'a> = RawEvent<'a>;
    // type Plugin = crate::GcpAuditPlugin;
    // const EVENT_SOURCE: &'static str = crate::PLUGIN_EVENT_SOURCE;
    type ExtractContext = Option<serde_json::Value>;
    const EXTRACT_FIELDS: &'static [ExtractFieldInfo<Self>] = &[
        field("gcp.user", &Self::extract_user)
            .with_display("User").with_description("GCP principal email who committed the action"),
        field("gcp.callerIP", &Self::extract_caller_ip)
            .with_display("Caller IP").with_description("GCP principal caller IP"),
        field("gcp.userAgent", &Self::extract_user_agent)
            .with_display("User Agent").with_description("GCP principal caller useragent"),
        field("gcp.authorizationInfo", &Self::extract_authorization_info)
            .with_display("Authorization Info").with_description("GCP authorization information affected resource"),
        field("gcp.serviceName", &Self::extract_service_name)
            .with_display("Service Name").with_description("GCP API service name"),
        field("gcp.policyDelta", &Self::extract_policy_delta)
            .with_display("Policy Delta").with_description("GCP service resource access policy"),
        field("gcp.request", &Self::extract_request)
            .with_display("Request").with_description("GCP API raw request"),
        field("gcp.methodName", &Self::extract_method_name)
            .with_display("Method Name").with_description("GCP API service method executed"),
        field("gcp.cloudfunctions.function", &Self::extract_cloudfunctions_function)
            .with_display("Cloud Function").with_description("GCF name"),
        field("gcp.cloudsql.databaseId", &Self::extract_cloudsql_database_id)
            .with_display("Cloud SQL Database ID").with_description("GCP SQL database ID"),
        field("gcp.compute.instanceId", &Self::extract_compute_instance_id)
            .with_display("Compute Instance ID").with_description("GCE instance ID"),
        field("gcp.compute.networkId", &Self::extract_compute_network_id)
            .with_display("Compute Network ID").with_description("GCP network ID"),
        field("gcp.compute.subnetwork", &Self::extract_compute_subnetwork)
            .with_display("Compute Subnetwork").with_description("GCP subnetwork name"),
        field("gcp.compute.subnetworkId", &Self::extract_compute_subnetwork_id)
            .with_display("Compute Subnetwork ID").with_description("GCP subnetwork ID"),
        field("gcp.dns.zone", &Self::extract_dns_zone)
            .with_display("DNS Zone").with_description("GCP DNS zone"),
        field("gcp.iam.serviceAccount", &Self::extract_iam_service_account)
            .with_display("IAM Service Account").with_description("GCP service account"),
        field("gcp.iam.serviceAccountId", &Self::extract_iam_service_account_id)
            .with_display("IAM Service Account ID").with_description("GCP IAM unique ID"),
        field("gcp.location", &Self::extract_location)
            .with_display("Location").with_description("GCP region"),
        field("gcp.logging.sink", &Self::extract_logging_sink)
            .with_display("Logging Sink").with_description("GCP logging sink"),
        field("gcp.projectId", &Self::extract_project_id)
            .with_display("Project ID").with_description("GCP project ID"),
        field("gcp.resourceName", &Self::extract_resource_name)
            .with_display("Resource Name").with_description("GCP resource name"),
        field("gcp.resourceType", &Self::extract_resource_type)
            .with_display("Resource Type").with_description("GCP resource type"),
        field("gcp.resourceLabels", &Self::extract_resource_labels)
            .with_display("Resource Labels").with_description("GCP resource labels"),
        field("gcp.storage.bucket", &Self::extract_storage_bucket)
            .with_display("Storage Bucket").with_description("GCP bucket name"),
        field("gcp.time", &Self::extract_time)
            .with_display("Event Time").with_description("Timestamp of the event in RFC3339 format"),
    ];

    fn get_fields(&mut self) -> &[ExtractFieldInfo<Self>] {
        &[
            ExtractFieldInfo::new("gcp.userAgent", "GCP principal caller useragent"),
            ExtractFieldInfo::new("gcp.authorizationInfo", "GCP authorization information affected resource"),
            ExtractFieldInfo::new("gcp.serviceName", "GCP API service name"),
            ExtractFieldInfo::new("gcp.policyDelta", "GCP service resource access policy"),
            ExtractFieldInfo::new("gcp.request", "GCP API raw request"),
            ExtractFieldInfo::new("gcp.methodName", "GCP API service method executed"),
            ExtractFieldInfo::new("gcp.cloudfunctions.function", "GCF name"),
            ExtractFieldInfo::new("gcp.cloudsql.databaseId", "GCP SQL database ID"),
            ExtractFieldInfo::new("gcp.compute.instanceId", "GCE instance ID"),
            ExtractFieldInfo::new("gcp.compute.networkId", "GCP network ID"),
            ExtractFieldInfo::new("gcp.compute.subnetwork", "GCP subnetwork name"),
            ExtractFieldInfo::new("gcp.compute.subnetworkId", "GCP subnetwork ID"),
            ExtractFieldInfo::new("gcp.dns.zone", "GCP DNS zone"),
            ExtractFieldInfo::new("gcp.iam.serviceAccount", "GCP service account"),
            ExtractFieldInfo::new("gcp.iam.serviceAccountId", "GCP IAM unique ID"),
            ExtractFieldInfo::new("gcp.location", "GCP region"),
            ExtractFieldInfo::new("gcp.logging.sink", "GCP logging sink"),
            ExtractFieldInfo::new("gcp.projectId", "GCP project ID"),
            ExtractFieldInfo::new("gcp.resourceName", "GCP resource name"),
            ExtractFieldInfo::new("gcp.resourceType", "GCP resource type"),
            ExtractFieldInfo::new("gcp.resourceLabels", "GCP resource labels"),
            ExtractFieldInfo::new("gcp.storage.bucket", "GCP bucket name"),
            ExtractFieldInfo::new("gcp.time", "Timestamp of the event in RFC3339 format"),
        ]
    }

}
