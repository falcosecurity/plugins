// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package gcpaudit

import (
	"fmt"
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "gcp.user", Display: "User", Desc: "GCP principal email who committed the action"},
		{Type: "string", Name: "gcp.callerIP", Display: "Caller IP", Desc: "GCP principal caller IP"},
		{Type: "string", Name: "gcp.userAgent", Display: "User Agent", Desc: "GCP principal caller useragent"},
		{Type: "string", Name: "gcp.authorizationInfo", Display: "Authorization Info", Desc: "GCP authorization information affected resource"},
		{Type: "string", Name: "gcp.serviceName", Display: "Service Name", Desc: "GCP API service name"},
		{Type: "string", Name: "gcp.policyDelta", Display: "Policy", Desc: "GCP service resource access policy"},
		{Type: "string", Name: "gcp.request", Display: "Request", Desc: "GCP API raw request"},
		{Type: "string", Name: "gcp.methodName", Display: "Method", Desc: "GCP API service method executed"},
		{Type: "string", Name: "gcp.cloudfunctions.function", Display: "Function Name", Desc: "GCF name"},
		{Type: "string", Name: "gcp.cloudsql.databaseId", Display: "Database ID", Desc: "GCP SQL database ID"},
		{Type: "string", Name: "gcp.compute.instanceId", Display: "Instance ID", Desc: "GCE instance ID"},
		{Type: "string", Name: "gcp.compute.networkId", Display: "Network ID", Desc: "GCP network ID"},
		{Type: "string", Name: "gcp.compute.subnetwork", Display: "Subnetwork Name", Desc: "GCP subnetwork name"},
		{Type: "string", Name: "gcp.compute.subnetworkId", Display: "Subnetwork ID", Desc: "GCP subnetwork ID"},
		{Type: "string", Name: "gcp.dns.zone", Display: "DNS Zone", Desc: "GCP DNS zoned"},
		{Type: "string", Name: "gcp.iam.serviceAccount", Display: "Service Account", Desc: "GCP service account"},
		{Type: "string", Name: "gcp.iam.serviceAccountId", Display: "Service Account ID", Desc: "GCP IAM unique ID"},
		{Type: "string", Name: "gcp.location", Display: "Location", Desc: "GCP region"},
		{Type: "string", Name: "gcp.logging.sink", Display: "Sink", Desc: "GCP logging sink"},
		{Type: "string", Name: "gcp.projectId", Display: "Project ID", Desc: "GCP project ID"},
		{Type: "string", Name: "gcp.resourceName", Display: "Resource Name", Desc: "GCP resource name"},
		{Type: "string", Name: "gcp.resourceType", Display: "Resource Type", Desc: "GCP resource type"},
		{Type: "string", Name: "gcp.resourceLabels", Display: "Resource Labels", Desc: "GCP resource labels"},
		{Type: "string", Name: "gcp.storage.bucket", Display: "Bucket Name", Desc: "GCP bucket name"},
		{Type: "string", Name: "gcp.time", Display: "Timestamp of the event", Desc: "Timestamp of the event in RFC3339 format"},
	}
}

func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	if evt.EventNum() != p.lastEventNum {
		evtBytes, err := io.ReadAll(evt.Reader())
		if err != nil {
			return err
		}
		evtString := string(evtBytes)
		p.jdata, err = p.jparser.Parse(evtString)
		if err != nil {
			return err
		}
		p.lastEventNum = evt.EventNum()
	}

	var fsval *fastjson.Value

	switch req.Field() {
	case "gcp.user":
		fsval = p.jdata.Get("protoPayload", "authenticationInfo", "principalEmail")

	case "gcp.callerIP":
		fsval = p.jdata.Get("protoPayload", "requestMetadata", "callerIp")

	case "gcp.userAgent":
		fsval = p.jdata.Get("protoPayload", "requestMetadata", "callerSuppliedUserAgent")

	case "gcp.authorizationInfo":
		fsval = p.jdata.Get("protoPayload", "authorizationInfo")

	case "gcp.serviceName":
		fsval = p.jdata.Get("protoPayload", "serviceName")

	case "gcp.request":
		fsval = p.jdata.Get("protoPayload", "request")

	case "gcp.policyDelta":
		resource := string(p.jdata.Get("resource").Get("type").GetStringBytes())

		if resource == "gcs_bucket" {
			fsval = p.jdata.Get("protoPayload", "serviceData", "policyDelta", "bindingDeltas")
		} else {
			fsval = p.jdata.Get("protoPayload", "metadata", "datasetChange", "bindingDeltas")
		}

	case "gcp.methodName":
		fsval = p.jdata.Get("protoPayload", "methodName")

	case "gcp.cloudfunctions.function":
		fsval = p.jdata.Get("resource", "labels", "function_name")

	case "gcp.cloudsql.databaseId":
		fsval = p.jdata.Get("resource", "labels", "database_id")

	case "gcp.compute.instanceId":
		fsval = p.jdata.Get("resource", "labels", "instance_id")

	case "gcp.compute.networkId":
		fsval = p.jdata.Get("resource", "labels", "network_id")

	case "gcp.compute.subnetwork":
		fsval = p.jdata.Get("resource", "labels", "subnetwork_name")

	case "gcp.compute.subnetworkId":
		fsval = p.jdata.Get("resource", "labels", "subnetwork_id")

	case "gcp.dns.zone":
		fsval = p.jdata.Get("resource", "labels", "zone_name")

	case "gcp.iam.serviceAccount":
		fsval = p.jdata.Get("resource", "labels", "email_id")

	case "gcp.iam.serviceAccountId":
		fsval = p.jdata.Get("resource", "labels", "unique_id")

	case "gcp.location":
		fsval = p.jdata.Get("resource", "labels", "location")
		if fsval == nil {
			// if location is not present, check for region
			fsval = p.jdata.Get("resource", "labels", "region")
			if fsval == nil {
				// if region is not present, check for zone
				val := p.jdata.Get("resource").Get("labels").Get("zone").GetStringBytes()
				if val != nil {
					zone := string(val)
					if len(zone) > 2 {
						// if in format: "us-central1-a", remove last two chars
						formattedZone := zone[:len(zone)-2]
						req.SetValue(formattedZone)
						return nil
					} else if zone != "" {
						req.SetValue(zone)
						return nil
					}
				}
			}
		}

	case "gcp.logging.sink":
		resource := string(p.jdata.Get("resource").Get("type").GetStringBytes())

		if resource == "logging_sink" {
			fsval = p.jdata.Get("resource", "labels", "name")
		}

	case "gcp.projectId":
		fsval = p.jdata.Get("resource", "labels", "project_id")

	case "gcp.resourceName":
		fsval = p.jdata.Get("protoPayload", "resourceName")

	case "gcp.resourceType":
		fsval = p.jdata.Get("resource", "type")

	case "gcp.resourceLabels":
		fsval = p.jdata.Get("resource", "labels")
		if fsval != nil {
			resourceLabels := fsval.MarshalTo(nil)
			if len(resourceLabels) > 0 {
				req.SetValue(string(resourceLabels))
				if req.WantOffset() {
					req.SetValueOffset(sdk.PluginEventPayloadOffset + uint32(fsval.Offset()), uint32(fsval.Len()))
				}
			}
		}
		return nil
	case "gcp.storage.bucket":
		fsval = p.jdata.Get("resource", "labels", "bucket_name")

	case "gcp.time":
		fsval = p.jdata.Get("timestamp")
	default:
		return fmt.Errorf("unknown field: %s", req.Field())
	}

	if fsval == nil {
		// return fmt.Errorf("unable to extract field: %s", req.Field())
		return nil
	}

	req.SetValue(string(fsval.GetStringBytes()))
	if req.WantOffset() {
		req.SetValueOffset(sdk.PluginEventPayloadOffset + uint32(fsval.Offset()), uint32(fsval.Len()))
	}

	return nil
}
