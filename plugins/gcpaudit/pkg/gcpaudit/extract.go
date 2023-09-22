package gcpaudit

import (
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
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

// Extract a field value from an event.
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.lastEventNum {
		// Read the event data
		data, err := io.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return err
		}
		p.lastEventNum = evt.EventNum()
	}

	// Extract the field value
	present, value := getfieldStr(p.jdata, req.Field())
	if present {
		req.SetValue(value)
	}

	return nil
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	switch field {
	case "gcp.user":
		res = string(jdata.Get("protoPayload").Get("authenticationInfo").Get("principalEmail").GetStringBytes())
	case "gcp.callerIP":
		res = string(jdata.Get("protoPayload").Get("requestMetadata").Get("callerIp").GetStringBytes())
	case "gcp.userAgent":
		res = string(jdata.Get("protoPayload").Get("requestMetadata").Get("callerSuppliedUserAgent").GetStringBytes())
	case "gcp.authorizationInfo":
		res = string(jdata.Get("protoPayload").Get("authorizationInfo").GetStringBytes())
	case "gcp.serviceName":
		res = string(jdata.Get("protoPayload").Get("serviceName").GetStringBytes())
	case "gcp.request":
		res = string(jdata.Get("protoPayload").Get("request").GetStringBytes())
	case "gcp.policyDelta":
		resource := string(jdata.Get("resource").Get("type").GetStringBytes())
		if resource == "gcs_bucket" {
			res = string(jdata.Get("protoPayload").Get("serviceData").Get("policyDelta").Get("bindingDeltas").GetStringBytes())
		} else {
			res = string(jdata.Get("protoPayload").Get("metadata").Get("datasetChange").Get("bindingDeltas").GetStringBytes())
		}
	case "gcp.methodName":
		res = string(jdata.Get("protoPayload").Get("methodName").GetStringBytes())
	case "gcp.cloudfunctions.function":
		res = string(jdata.Get("resource").Get("labels").Get("function_name").GetStringBytes())
	case "gcp.cloudsql.databaseId":
		res = string(jdata.Get("resource").Get("labels").Get("database_id").GetStringBytes())
	case "gcp.compute.instanceId":
		res = string(jdata.Get("resource").Get("labels").Get("instance_id").GetStringBytes())
	case "gcp.compute.networkId":
		res = string(jdata.Get("resource").Get("labels").Get("network_id").GetStringBytes())
	case "gcp.compute.subnetwork":
		res = string(jdata.Get("resource").Get("labels").Get("subnetwork_name").GetStringBytes())
	case "gcp.compute.subnetworkId":
		res = string(jdata.Get("resource").Get("labels").Get("subnetwork_id").GetStringBytes())
	case "gcp.dns.zone":
		res = string(jdata.Get("resource").Get("labels").Get("zone_name").GetStringBytes())
	case "gcp.iam.serviceAccount":
		res = string(jdata.Get("resource").Get("labels").Get("email_id").GetStringBytes())
	case "gcp.iam.serviceAccountId":
		res = string(jdata.Get("resource").Get("labels").Get("unique_id").GetStringBytes())
	case "gcp.location":
		res = string(jdata.Get("resource").Get("labels").Get("location").GetStringBytes())
		if res != "" {
			break
		}
		// if location is not present, check for region
		res = string(jdata.Get("resource").Get("labels").Get("region").GetStringBytes())
		if res != "" {
			break
		}
		// if region is not present, check for zone
		res = string(jdata.Get("resource").Get("labels").Get("zone").GetStringBytes())
		if len(res) > 2 {
			// if in format: "us-central1-a", remove last two chars
			res = res[:len(res)-2]
		}
	case "gcp.logging.sink":
		resource := string(jdata.Get("resource").Get("type").GetStringBytes())
		if resource == "logging_sink" {
			res = string(jdata.Get("resource").Get("labels").Get("name").GetStringBytes())
		}
	case "gcp.projectId":
		res = string(jdata.Get("resource").Get("labels").Get("project_id").GetStringBytes())
	case "gcp.resourceName":
		res = string(jdata.Get("protoPayload").Get("resourceName").GetStringBytes())
	case "gcp.resourceType":
		res = string(jdata.Get("resource").Get("type").GetStringBytes())
	case "gcp.storage.bucket":
		res = string(jdata.Get("resource").Get("labels").Get("bucket_name").GetStringBytes())
	default:
		return false, ""
	}

	return true, res
}
