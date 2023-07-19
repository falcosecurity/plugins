package gcpaudit

import (
	"fmt"
	"io/ioutil"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

func (auditlogsPlugin *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "gcp.user", Desc: "GCP principal email who committed the action"},
		{Type: "string", Name: "gcp.callerIP", Desc: "GCP principal caller IP"},
		{Type: "string", Name: "gcp.userAgent", Desc: "GCP principal caller useragent"},
		{Type: "string", Name: "gcp.authorizationInfo", Desc: "GCP authorization information affected resource"},
		{Type: "string", Name: "gcp.serviceName", Desc: "GCP API service name"},
		{Type: "string", Name: "gcp.policyDelta", Desc: "GCP service resource access policy"},
		{Type: "string", Name: "gcp.request", Desc: "GCP API raw request"},
		{Type: "string", Name: "gcp.methodName", Desc: "GCP API service  method executed"},
	}
}

func (auditlogsPlugin *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {

	if evt.EventNum() != auditlogsPlugin.lastEventNum {

		evtBytes, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}
		evtString := string(evtBytes)

		auditlogsPlugin.jdata, err = auditlogsPlugin.jparser.Parse(evtString)
		if err != nil {
			return err
		}
		auditlogsPlugin.jdataEvtnum = evt.EventNum()

	}

	switch req.Field() {

	case "gcp.user":
		principalEmail := string(auditlogsPlugin.jdata.Get("protoPayload").Get("authenticationInfo").Get("principalEmail").GetStringBytes())
		req.SetValue(principalEmail)

	case "gcp.callerIP":
		principalIP := string(auditlogsPlugin.jdata.Get("protoPayload").Get("requestMetadata").Get("callerIp").GetStringBytes())
		req.SetValue(principalIP)

	case "gcp.userAgent":
		principalUserAgent := auditlogsPlugin.jdata.Get("protoPayload").Get("requestMetadata").Get("callerSuppliedUserAgent")
		if principalUserAgent != nil {
			req.SetValue(string(principalUserAgent.GetStringBytes()))
		} else {
			fmt.Println("Principal User Agent was omitted!")
		}

	case "gcp.authorizationInfo":
		principalAuthorizationInfo := auditlogsPlugin.jdata.Get("protoPayload").Get("authorizationInfo")
		if principalAuthorizationInfo.Exists() {
			req.SetValue(principalAuthorizationInfo.String())
		} else {
			fmt.Println("Authorization info was omitted!")
		}

	case "gcp.serviceName":
		serviceName := auditlogsPlugin.jdata.Get("protoPayload").Get("serviceName")
		if serviceName.Exists() {
			req.SetValue(string(serviceName.GetStringBytes()))
		} else {
			fmt.Println("Service name was omitted!")
		}

	case "gcp.request":
		request := auditlogsPlugin.jdata.Get("protoPayload").Get("request").String()
		req.SetValue(request)

	case "gcp.policyDelta":
		resource := string(auditlogsPlugin.jdata.Get("resource").Get("type").GetStringBytes())

		if resource == "gcs_bucket" {
			bindingDeltas := auditlogsPlugin.jdata.Get("protoPayload").Get("serviceData").Get("policyDelta").Get("bindingDeltas").String()

			req.SetValue(bindingDeltas)
		} else {
			bindingDeltas := auditlogsPlugin.jdata.Get("protoPayload").Get("metadata").Get("datasetChange").Get("bindingDeltas").String()
			req.SetValue(bindingDeltas)
		}

	case "gcp.methodName":
		serviceName := string(auditlogsPlugin.jdata.Get("protoPayload").Get("methodName").GetStringBytes())
		req.SetValue(serviceName)

	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}
	return nil
}
