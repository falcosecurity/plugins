package gcpaudit

import (
	"fmt"
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "gcp.user", Desc: "GCP principal email who committed the action"},
		{Type: "string", Name: "gcp.callerIP", Desc: "GCP principal caller IP"},
		{Type: "string", Name: "gcp.userAgent", Desc: "GCP principal caller useragent"},
		{Type: "string", Name: "gcp.authorizationInfo", Desc: "GCP authorization information affected resource"},
		{Type: "string", Name: "gcp.serviceName", Desc: "GCP API service name"},
		{Type: "string", Name: "gcp.policyDelta", Desc: "GCP service resource access policy"},
		{Type: "string", Name: "gcp.request", Desc: "GCP API raw request"},
		{Type: "string", Name: "gcp.methodName", Desc: "GCP API service method executed"},
		{Type: "string", Name: "gcp.cloudfunctions.function", Desc: "GCF name"},
		{Type: "string", Name: "gcp.cloudsql.databaseId", Desc: "GCP SQL database ID"},
		{Type: "string", Name: "gcp.compute.instanceId", Desc: "GCE instance ID"},
		{Type: "string", Name: "gcp.compute.networkId", Desc: "GCP network ID"},
		{Type: "string", Name: "gcp.compute.subnetwork", Desc: "GCP subnetwork name"},
		{Type: "string", Name: "gcp.compute.subnetworkId", Desc: "GCP subnetwork ID"},
		{Type: "string", Name: "gcp.dns.zone", Desc: "GCP DNS zoned"},
		{Type: "string", Name: "gcp.iam.serviceAccount", Desc: "GCP service account"},
		{Type: "string", Name: "gcp.iam.serviceAccountId", Desc: "GCP IAM unique ID"},
		{Type: "string", Name: "gcp.location", Desc: "GCP region"},
		{Type: "string", Name: "gcp.logging.sink", Desc: "GCP logging sink"},
		{Type: "string", Name: "gcp.projectId", Desc: "GCP project ID"},
		{Type: "string", Name: "gcp.resourceName", Desc: "GCP resource name"},
		{Type: "string", Name: "gcp.resourceType", Desc: "GCP resource type"},
		{Type: "string", Name: "gcp.storage.bucket", Desc: "GCP bucket name"},
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
		functionName := p.jdata.Get("resource").Get("labels").Get("function_name")
		if functionName.Exists() {
			req.SetValue(functionName)
		}

	case "gcp.cloudsql.databaseId":
		databaseId := p.jdata.Get("resource").Get("labels").Get("database_id")
		if databaseId.Exists() {
			req.SetValue(databaseId)
		}

	case "gcp.compute.instanceId":
		instanceId := p.jdata.Get("resource").Get("labels").Get("instance_id")
		if instanceId.Exists() {
			req.SetValue(instanceId)
		}

	case "gcp.compute.networkId":
		networkId := p.jdata.Get("resource").Get("labels").Get("network_id")
		if networkId.Exists() {
			req.SetValue(networkId)
		}

	case "gcp.compute.subnetwork":
		subnetwork := p.jdata.Get("resource").Get("labels").Get("subnetwork_name")
		if subnetwork.Exists() {
			req.SetValue(subnetwork)
		}

	case "gcp.compute.subnetworkId":
		subnetworkId := p.jdata.Get("resource").Get("labels").Get("subnetwork_id")
		if subnetworkId.Exists() {
			req.SetValue(subnetworkId)
		}

	case "gcp.dns.zone":
		zone := p.jdata.Get("resource").Get("labels").Get("zone_name")
		if zone.Exists() {
			req.SetValue(zone)
		}

	case "gcp.iam.serviceAccount":
		serviceAccount := p.jdata.Get("resource").Get("labels").Get("email_id")
		if serviceAccount.Exists() {
			req.SetValue(serviceAccount)
		}

	case "gcp.iam.serviceAccountId":
		serviceAccountId := p.jdata.Get("resource").Get("labels").Get("unique_id")
		if serviceAccountId.Exists() {
			req.SetValue(serviceAccountId)
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
		zone := p.jdata.Get("resource").Get("labels").Get("zone").String()
		if zone != "" && len(zone) > 2 {
			// if in format: "us-central1-a", remove last two chars
			formattedZone := zone[:len(zone)-2]
			req.SetValue(formattedZone)
		} else if zone != "" {
			req.SetValue(zone)
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
		projectId := p.jdata.Get("resource").Get("labels").Get("project_id")
		if projectId.Exists() {
			req.SetValue(projectId)
		}

	case "gcp.resourceName":
		resourceName := p.jdata.Get("protoPayload").Get("resourceName")
		if resourceName.Exists() {
			req.SetValue(resourceName)
		}

	case "gcp.resourceType":
		resourceType := p.jdata.Get("resource").Get("type")
		if resourceType.Exists() {
			req.SetValue(resourceType)
		}

	case "gcp.storage.bucket":
		bucket := p.jdata.Get("resource").Get("labels").Get("bucket_name")
		if bucket.Exists() {
			req.SetValue(bucket)
		}

	default:
		return fmt.Errorf("unknown field: %s", req.Field())
	}

	return nil
}
