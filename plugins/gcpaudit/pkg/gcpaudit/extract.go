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
		{Type: "string", Name: "gcp.storage.bucket", Display: "Bucket Name", Desc: "GCP bucket name"},
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

	switch req.Field() {
	case "gcp.user":
		principalEmail := string(p.jdata.Get("protoPayload").Get("authenticationInfo").Get("principalEmail").GetStringBytes())
		req.SetValue(principalEmail)

	case "gcp.callerIP":
		principalIP := string(p.jdata.Get("protoPayload").Get("requestMetadata").Get("callerIp").GetStringBytes())
		req.SetValue(principalIP)

	case "gcp.userAgent":
		principalUserAgent := p.jdata.Get("protoPayload").Get("requestMetadata").GetStringBytes("callerSuppliedUserAgent")
		if principalUserAgent != nil {
			req.SetValue(string(principalUserAgent))
		}

	case "gcp.authorizationInfo":
		principalAuthorizationInfo := p.jdata.Get("protoPayload").GetStringBytes("authorizationInfo")
		if principalAuthorizationInfo != nil {
			req.SetValue(string(principalAuthorizationInfo))
		}

	case "gcp.serviceName":
		serviceName := p.jdata.Get("protoPayload").Get("serviceName")
		if serviceName.Exists() {
			req.SetValue(string(serviceName.GetStringBytes()))
		}

	case "gcp.request":
		request := p.jdata.Get("protoPayload").GetStringBytes("request")
		if request != nil {
			req.SetValue(string(request))
		}

	case "gcp.policyDelta":
		resource := string(p.jdata.Get("resource").Get("type").GetStringBytes())

		if resource == "gcs_bucket" {
			bindingDeltas := p.jdata.Get("protoPayload").Get("serviceData").Get("policyDelta").GetStringBytes("bindingDeltas")
			if bindingDeltas != nil {
				req.SetValue(string(bindingDeltas))
			}
		} else {
			bindingDeltas := p.jdata.Get("protoPayload").Get("metadata").Get("datasetChange").GetStringBytes("bindingDeltas")
			if bindingDeltas != nil {
				req.SetValue(string(bindingDeltas))
			}
		}

	case "gcp.methodName":
		methodName := string(p.jdata.Get("protoPayload").Get("methodName").GetStringBytes())
		req.SetValue(methodName)

	case "gcp.cloudfunctions.function":
		functionName := p.jdata.Get("resource").Get("labels").GetStringBytes("function_name")
		if functionName != nil {
			req.SetValue(string(functionName))
		}

	case "gcp.cloudsql.databaseId":
		databaseId := p.jdata.Get("resource").Get("labels").GetStringBytes("database_id")
		if databaseId != nil {
			req.SetValue(string(databaseId))
		}

	case "gcp.compute.instanceId":
		instanceId := p.jdata.Get("resource").Get("labels").GetStringBytes("instance_id")
		if instanceId != nil {
			req.SetValue(string(instanceId))
		}

	case "gcp.compute.networkId":
		networkId := p.jdata.Get("resource").Get("labels").GetStringBytes("network_id")
		if networkId != nil {
			req.SetValue(string(networkId))
		}

	case "gcp.compute.subnetwork":
		subnetwork := p.jdata.Get("resource").Get("labels").GetStringBytes("subnetwork_name")
		if subnetwork != nil {
			req.SetValue(string(subnetwork))
		}

	case "gcp.compute.subnetworkId":
		subnetworkId := p.jdata.Get("resource").Get("labels").GetStringBytes("subnetwork_id")
		if subnetworkId != nil {
			req.SetValue(string(subnetworkId))
		}

	case "gcp.dns.zone":
		zone := p.jdata.Get("resource").Get("labels").GetStringBytes("zone_name")
		if zone != nil {
			req.SetValue(string(zone))
		}

	case "gcp.iam.serviceAccount":
		serviceAccount := p.jdata.Get("resource").Get("labels").GetStringBytes("email_id")
		if serviceAccount != nil {
			req.SetValue(string(serviceAccount))
		}

	case "gcp.iam.serviceAccountId":
		serviceAccountId := p.jdata.Get("resource").Get("labels").GetStringBytes("unique_id")
		if serviceAccountId != nil {
			req.SetValue(string(serviceAccountId))
		}

	case "gcp.location":
		location := p.jdata.Get("resource").Get("labels").GetStringBytes("location")
		if location != nil {
			req.SetValue(string(location))
			return nil
		}
		// if location is not present, check for region
		region := p.jdata.Get("resource").Get("labels").GetStringBytes("region")
		if region != nil {
			req.SetValue(string(region))
			return nil
		}
		// if region is not present, check for zone
		val := p.jdata.Get("resource").Get("labels").Get("zone").GetStringBytes()
		if val != nil {
			zone := string(val)
			if len(zone) > 2 {
				// if in format: "us-central1-a", remove last two chars
				formattedZone := zone[:len(zone)-2]
				req.SetValue(formattedZone)
			} else if zone != "" {
				req.SetValue(zone)
			}
		}

	case "gcp.logging.sink":
		resource := string(p.jdata.Get("resource").Get("type").GetStringBytes())

		if resource == "logging_sink" {
			loggingSink := p.jdata.Get("resource").Get("labels").Get("name")
			if loggingSink.Exists() {
				req.SetValue(loggingSink)
			}
		}

	case "gcp.projectId":
		projectId := p.jdata.Get("resource").Get("labels").GetStringBytes("project_id")
		if projectId != nil {
			req.SetValue(string(projectId))
		}

	case "gcp.resourceName":
		resourceName := p.jdata.Get("protoPayload").GetStringBytes("resourceName")
		if resourceName != nil {
			req.SetValue(string(resourceName))
		}

	case "gcp.resourceType":
		resourceType := p.jdata.Get("resource").GetStringBytes("type")
		if resourceType != nil {
			req.SetValue(string(resourceType))
		}

	case "gcp.storage.bucket":
		bucket := p.jdata.Get("resource").Get("labels").GetStringBytes("bucket_name")
		if bucket != nil {
			req.SetValue(string(bucket))
		}

	default:
		return fmt.Errorf("unknown field: %s", req.Field())
	}

	return nil
}
