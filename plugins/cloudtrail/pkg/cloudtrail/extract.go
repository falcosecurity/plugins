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

package cloudtrail

import (
	"fmt"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

// AWS CloudTrail log event reference:
// https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
// AWS CloudTrail record contents:
// https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html

var supportedFields = []sdk.FieldEntry{
	{Type: "string", Name: "ct.id", Display: "Event ID", Desc: "the unique ID of the cloudtrail event (eventID in the json)."},
	{Type: "string", Name: "ct.error", Display: "Error Code", Desc: "The error code from the event. Will be \"<NA>\" (e.g. the NULL/empty/none value) if there was no error."},
	{Type: "string", Name: "ct.errormessage", Display: "Error Message", Desc: "The description of an error. Will be \"<NA>\" (e.g. the NULL/empty/none value) if there was no error."},
	{Type: "string", Name: "ct.time", Display: "Timestamp", Desc: "the timestamp of the cloudtrail event (eventTime in the json).", Properties: []string{"hidden"}},
	{Type: "string", Name: "ct.src", Display: "AWS Service", Desc: "the source of the cloudtrail event (eventSource in the json)."},
	{Type: "string", Name: "ct.shortsrc", Display: "AWS Service", Desc: "the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer)."},
	{Type: "string", Name: "ct.name", Display: "Event Name", Desc: "the name of the cloudtrail event (eventName in the json)."},
	{Type: "string", Name: "ct.user", Display: "User Name", Desc: "the user of the cloudtrail event (userIdentity.userName in the json).", Properties: []string{"conversation"}},
	{Type: "string", Name: "ct.user.accountid", Display: "User Account ID", Desc: "the account id of the user of the cloudtrail event."},
	{Type: "string", Name: "ct.user.identitytype", Display: "User Identity Type", Desc: "the kind of user identity (e.g. Root, IAMUser,AWSService, etc.)"},
	{Type: "string", Name: "ct.user.principalid", Display: "User Principal Id", Desc: "A unique identifier for the user that made the request."},
	{Type: "string", Name: "ct.user.arn", Display: "User ARN", Desc: "the Amazon Resource Name (ARN) of the user that made the request."},
	{Type: "string", Name: "ct.region", Display: "Region", Desc: "the region of the cloudtrail event (awsRegion in the json)."},
	{Type: "string", Name: "ct.response.subnetid", Display: "Response Subnet ID", Desc: "the subnet ID included in the response."},
	{Type: "string", Name: "ct.response.reservationid", Display: "Response Reservation ID", Desc: "the reservation ID included in the response."},
	{Type: "string", Name: "ct.response", Display: "Response Elements", Desc: "All response elements."},
	{Type: "string", Name: "ct.request.availabilityzone", Display: "Request Availability Zone", Desc: "the availability zone included in the request."},
	{Type: "string", Name: "ct.request.cluster", Display: "Request Cluster", Desc: "the cluster included in the request."},
	{Type: "string", Name: "ct.request.functionname", Display: "Request Function Name", Desc: "the function name included in the request."},
	{Type: "string", Name: "ct.request.groupname", Display: "Request Group Name", Desc: "the group name included in the request."},
	{Type: "string", Name: "ct.request.host", Display: "Request Host Name", Desc: "the host included in the request"},
	{Type: "string", Name: "ct.request.name", Display: "Host Name", Desc: "the name of the entity being acted on in the request."},
	{Type: "string", Name: "ct.request.policy", Display: "Host Policy", Desc: "the policy included in the request"},
	{Type: "string", Name: "ct.request.serialnumber", Display: "Request Serial Number", Desc: "the serial number provided in the request."},
	{Type: "string", Name: "ct.request.servicename", Display: "Request Service", Desc: "the service name provided in the request."},
	{Type: "string", Name: "ct.request.subnetid", Display: "Request Subnet ID", Desc: "the subnet ID provided in the request."},
	{Type: "string", Name: "ct.request.taskdefinition", Display: "Request Task Definition", Desc: "the task definition prrovided in the request."},
	{Type: "string", Name: "ct.request.username", Display: "Request User Name", Desc: "the username provided in the request."},
	{Type: "string", Name: "ct.request", Display: "Request Parameters", Desc: "All request parameters."},
	{Type: "string", Name: "ct.srcip", Display: "Source IP", Desc: "the IP address generating the event (sourceIPAddress in the json).", Properties: []string{"conversation"}},
	{Type: "string", Name: "ct.useragent", Display: "User Agent", Desc: "the user agent generating the event (userAgent in the json)."},
	{Type: "string", Name: "ct.info", Display: "Info", Desc: "summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details.", Properties: []string{"info"}},
	{Type: "string", Name: "ct.managementevent", Display: "Management Event", Desc: "'true' if the event is a management event (AwsApiCall, AwsConsoleAction, AwsConsoleSignIn, or AwsServiceEvent), 'false' otherwise."},
	{Type: "string", Name: "ct.readonly", Display: "Read Only", Desc: "'true' if the event only reads information (e.g. DescribeInstances), 'false' if the event modifies the state (e.g. RunInstances, CreateLoadBalancer...)."},
	{Type: "string", Name: "ct.requestid", Display: "Request ID", Desc: "The value that identifies the request."},
	{Type: "string", Name: "ct.eventtype", Display: "Event Type", Desc: "Identifies the type of event that generated the event record."},
	{Type: "string", Name: "ct.apiversion", Display: "API Version", Desc: "The API version associated with the AwsApiCall eventType value."},
	{Type: "string", Name: "ct.resources", Display: "Resources", Desc: "A list of resources accessed in the event."},
	{Type: "string", Name: "ct.recipientaccountid", Display: "Recipient Account Id", Desc: "The account ID that received this event."},
	{Type: "string", Name: "ct.serviceeventdetails", Display: "Service Event Details", Desc: "Identifies the service event, including what triggered the event and the result."},
	{Type: "string", Name: "ct.sharedeventid", Display: "Shared Event ID", Desc: "GUID generated by CloudTrail to uniquely identify CloudTrail events."},
	{Type: "string", Name: "ct.vpcendpointid", Display: "VPC Endpoint ID", Desc: "Identifies the VPC endpoint in which requests were made."},
	{Type: "string", Name: "ct.eventcategory", Display: "Event Category", Desc: "Shows the event category that is used in LookupEvents calls."},
	{Type: "string", Name: "ct.addendum.reason", Display: "Reason", Desc: "The reason that the event or some of its contents were missing."},
	{Type: "string", Name: "ct.addendum.updatedfields", Display: "Updated Fields", Desc: "The event record fields that are updated by the addendum."},
	{Type: "string", Name: "ct.addendum.originalrequestid", Display: "Original Request ID", Desc: "The original unique ID of the request."},
	{Type: "string", Name: "ct.addendum.originaleventid", Display: "Original Event ID", Desc: "The original event ID."},
	{Type: "string", Name: "ct.sessioncredentialfromconsole", Display: "Session Credential From Console", Desc: "Shows whether or not an event originated from an AWS Management Console session."},
	{Type: "string", Name: "ct.edgedevicedetails", Display: "Edge Device Details", Desc: "Information about edge devices that are targets of a request."},
	{Type: "string", Name: "ct.tlsdetails.tlsversion", Display: "TLS Version", Desc: "The TLS version of a request."},
	{Type: "string", Name: "ct.tlsdetails.ciphersuite", Display: "TLS Cipher Suite", Desc: "The cipher suite (combination of security algorithms used) of a request."},
	{Type: "string", Name: "ct.tlsdetails.clientprovidedhostheader", Display: "Client Provided Host Header", Desc: "The client-provided host name used in the service API call."},
	{Type: "string", Name: "ct.additionaleventdata", Display: "Additional Event Data", Desc: "All additional event data attributes."},
	{Type: "string", Name: "s3.uri", Display: "Key URI", Desc: "the s3 URI (s3://<bucket>/<key>).", Properties: []string{"conversation"}},
	{Type: "string", Name: "s3.bucket", Display: "Bucket Name", Desc: "the bucket name for s3 events.", Properties: []string{"conversation"}},
	{Type: "string", Name: "s3.key", Display: "Key Name", Desc: "the S3 key name."},
	{Type: "uint64", Name: "s3.bytes", Display: "Total Bytes", Desc: "the size of an s3 download or upload, in bytes."},
	{Type: "uint64", Name: "s3.bytes.in", Display: "Bytes In", Desc: "the size of an s3 upload, in bytes.", Properties: []string{"hidden"}},
	{Type: "uint64", Name: "s3.bytes.out", Display: "Bytes Out", Desc: "the size of an s3 download, in bytes.", Properties: []string{"hidden"}},
	{Type: "uint64", Name: "s3.cnt.get", Display: "N Get Ops", Desc: "the number of get operations. This field is 1 for GetObject events, 0 otherwise.", Properties: []string{"hidden"}},
	{Type: "uint64", Name: "s3.cnt.put", Display: "N Put Ops", Desc: "the number of put operations. This field is 1 for PutObject events, 0 otherwise.", Properties: []string{"hidden"}},
	{Type: "uint64", Name: "s3.cnt.other", Display: "N Other Ops", Desc: "the number of non I/O operations. This field is 0 for GetObject and PutObject events, 1 for all the other events.", Properties: []string{"hidden"}},
	{Type: "string", Name: "ec2.name", Display: "Instance Name", Desc: "the name of the ec2 instances, typically stored in the instance tags."},
	{Type: "string", Name: "ec2.imageid", Display: "Image Id", Desc: "the ID for the image used to run the ec2 instance in the response."},
	{Type: "string", Name: "ecr.repository", Display: "ECR Repository name", Desc: "the name of the ecr Repository specified in the request."},
	{Type: "string", Name: "ecr.imagetag", Display: "Image Tag", Desc: "the tag of the image specified in the request."},
	{Type: "string", Name: "iam.role", Display: "IAM Role", Desc: "the IAM role specified in the request."},
	{Type: "string", Name: "iam.policy", Display: "IAM Policy", Desc: "the IAM policy specified in the request."},
}

func getUser(jdata *fastjson.Value) (bool, string, int, int) {
	jutype := jdata.GetStringBytes("userIdentity", "type")

	if jutype == nil {
		return false, "", 0, 0
	}

	utype := string(jutype)

	var jun *fastjson.Value

	switch utype {
	case "Root", "IAMUser":
		jun = jdata.Get("userIdentity", "userName")
	case "AWSService":
		jun = jdata.Get("userIdentity", "invokedBy")
	case "AssumedRole":
		jun = jdata.Get("userIdentity", "sessionContext", "sessionIssuer", "userName")
		if jun == nil {
			return true, "AssumedRole", 0, 0
		}
	case "AWSAccount":
		return true, "AWSAccount", 0, 0
	case "FederatedUser":
		return true, "FederatedUser", 0, 0
	default:
		return false, "<unknown user type>", 0, 0
	}

	if jun != nil {
		return true, string(jun.GetStringBytes()), jun.Offset(), jun.Len()
	}

	return false, "<NA>", 0, 0
}

func getEvtInfo(jdata *fastjson.Value) string {
	var present bool
	var evtuser string
	var evtsrcip string
	var evtname string
	var errsymbol string
	var evtreadonly string
	var rwsymbol string
	var info string

	// Start the info field "who" (ct.user), "where" (ct.srcip), and "what" (ct.name)
	// along with read/write and error status.
	present, evtuser, _, _ = getfieldStr(jdata, "ct.user")
	if !present {
		return "<invalid cloudtrail event: userIdentity field missing>"
	}

	present, evtsrcip, _, _ = getfieldStr(jdata, "ct.srcip")
	if !present {
		return "<invalid cloudtrail event: eventSource field missing>"
	}

	errsymbol = ""
	present, _, _, _ = getfieldStr(jdata, "ct.error")
	if present {
		errsymbol = "!"
	}

	rwsymbol = "←"
	present, evtreadonly, _, _ = getfieldStr(jdata, "ct.readonly")
	if present && evtreadonly == "false" {
		rwsymbol = "→"
	}

	present, evtname, _, _ = getfieldStr(jdata, "ct.name")
	if !present {
		return "<invalid cloudtrail event: eventName field missing>"
	}

	if evtuser == evtsrcip {
		info = fmt.Sprintf("%v %v%v %v", evtuser, errsymbol, rwsymbol, evtname)
	} else {
		info = fmt.Sprintf("%v via %v %v%v %v", evtuser, evtsrcip, errsymbol, rwsymbol, evtname)
	}

	switch evtname {
	case "PutBucketPublicAccessBlock":
		jpac := jdata.GetObject("requestParameters", "PublicAccessBlockConfiguration")
		if jpac != nil {
			info += fmt.Sprintf(" BlockPublicAcls=%v BlockPublicPolicy=%v IgnorePublicAcls=%v RestrictPublicBuckets=%v ",
				jdata.GetBool("BlockPublicAcls"),
				jdata.GetBool("BlockPublicPolicy"),
				jdata.GetBool("IgnorePublicAcls"),
				jdata.GetBool("RestrictPublicBuckets"),
			)
		}
		return info
	default:
	}

	present, u64val, _, _ := getfieldU64(jdata, "s3.bytes")
	if present {
		info += fmt.Sprintf(" Size=%v", u64val)
	}

	present, val, _, _ := getfieldStr(jdata, "s3.uri")
	if present {
		info += fmt.Sprintf(" URI=%s", val)
		return info
	}

	present, val, _, _ = getfieldStr(jdata, "s3.bucket")
	if present {
		info += fmt.Sprintf(" Bucket=%s", val)
		return info
	}

	present, val, _, _ = getfieldStr(jdata, "s3.key")
	if present {
		info += fmt.Sprintf(" Key=%s", val)
		return info
	}

	present, val, _, _ = getfieldStr(jdata, "ct.request.host")
	if present {
		info += fmt.Sprintf(" Host=%s", val)
		return info
	}

	return info
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string, int, int) {
	var fsval *fastjson.Value

	// Go should do binary search here:
	// https://github.com/golang/go/blob/8ee9bca2729ead81da6bf5a18b87767ff396d1b7/src/cmd/compile/internal/gc/swt.go#L375
	switch field {
	case "ct.id":
		fsval = jdata.Get("eventID")
	case "ct.error":
		fsval = jdata.Get("errorCode")
	case "ct.errormessage":
		fsval = jdata.Get("errorMessage")
	case "ct.time":
		fsval = jdata.Get("eventTime")
	case "ct.src":
		fsval = jdata.Get("eventSource")
	case "ct.shortsrc":
		fsval = jdata.Get("eventSource")
		if fsval != nil {
			res := string(fsval.GetStringBytes())
			if len(res) > len(".amazonaws.com") {
				srctrailer := res[len(res)-len(".amazonaws.com"):]
				if srctrailer == ".amazonaws.com" {
					res = res[0 : len(res)-len(".amazonaws.com")]
					return true, res, fsval.Offset(), fsval.Len()
				}
			}
		}
	case "ct.name":
		fsval = jdata.Get("eventName")
	case "ct.user":
		present, res, offset, length := getUser(jdata)
		if !present {
			return false, "", 0, 0
		}
		return true, res, offset, length
	case "ct.user.accountid":
		fsval = jdata.Get("userIdentity", "accountId")
		if fsval == nil {
			fsval = jdata.Get("recipientAccountId")
		}
	case "ct.user.identitytype":
		fsval = jdata.Get("userIdentity", "type")
	case "ct.user.principalid":
		fsval = jdata.Get("userIdentity", "principalId")
	case "ct.user.arn":
		fsval = jdata.Get("userIdentity", "arn")
	case "ct.region":
		fsval = jdata.Get("awsRegion")
	case "ct.response.subnetid":
		fsval = jdata.Get("responseElements", "subnetId")
	case "ct.response.reservationid":
		fsval = jdata.Get("responseElements", "reservationId")
	case "ct.response":
		val := jdata.Get("responseElements")
		if val == nil {
			return false, "", 0, 0
		}
		return true, string(val.MarshalTo(nil)), val.Offset(), val.Len()
	case "ct.request.availabilityzone":
		fsval = jdata.Get("requestParameters", "availabilityZone")
	case "ct.request.cluster":
		fsval = jdata.Get("requestParameters", "cluster")
	case "ct.request.functionname":
		fsval = jdata.Get("requestParameters", "functionName")
	case "ct.request.groupname":
		fsval = jdata.Get("requestParameters", "groupName")
	case "ct.request.host":
		fsval = jdata.Get("requestParameters", "Host")
	case "ct.request.name":
		fsval = jdata.Get("requestParameters", "name")
	case "ct.request.policy":
		fsval = jdata.Get("requestParameters", "policy")
	case "ct.request.serialnumber":
		fsval = jdata.Get("requestParameters", "serialNumber")
	case "ct.request.servicename":
		fsval = jdata.Get("requestParameters", "serviceName")
	case "ct.request.subnetid":
		fsval = jdata.Get("requestParameters", "subnetId")
	case "ct.request.taskdefinition":
		fsval = jdata.Get("requestParameters", "taskDefinition")
	case "ct.request.username":
		fsval = jdata.Get("requestParameters", "userName")
	case "ct.request":
		val := jdata.Get("requestParameters")
		if val == nil {
			return false, "", 0, 0
		}
		return true, string(val.MarshalTo(nil)), val.Offset(), val.Len()
	case "ct.srcip":
		fsval = jdata.Get("sourceIPAddress")
	case "ct.useragent":
		fsval = jdata.Get("userAgent")
	case "ct.info":
		return true, getEvtInfo(jdata), 0, 0
	case "ct.managementevent":
		fsval := jdata.Get("managementEvent")
		if fsval != nil {
			res := "false"
			me, _ := fsval.Bool()
			if me {
				res = "true"
			}
			return true, res, fsval.Offset(), fsval.Len()
		}
	case "ct.readonly":
		fsval = jdata.Get("readOnly")
		if fsval == nil {
			return false, "", 0, 0
		}
		ro, _ := fsval.Bool()
		var res string
		if ro {
			res = "true"
		} else {
			oro := jdata.Get("readOnly")
			if oro == nil {
				//
				// Once in a while, events without the readOnly property appear. We try to interpret them with the manual
				// heuristic below.
				//
				val := jdata.GetStringBytes("eventName")
				if val == nil {
					return false, "", 0, 0
				}
				ename := string(val)
				if strings.HasPrefix(ename, "Start") || strings.HasPrefix(ename, "Stop") || strings.HasPrefix(ename, "Create") ||
					strings.HasPrefix(ename, "Destroy") || strings.HasPrefix(ename, "Delete") || strings.HasPrefix(ename, "Add") ||
					strings.HasPrefix(ename, "Remove") || strings.HasPrefix(ename, "Terminate") || strings.HasPrefix(ename, "Put") ||
					strings.HasPrefix(ename, "Associate") || strings.HasPrefix(ename, "Disassociate") || strings.HasPrefix(ename, "Attach") ||
					strings.HasPrefix(ename, "Detach") || strings.HasPrefix(ename, "Add") || strings.HasPrefix(ename, "Open") ||
					strings.HasPrefix(ename, "Close") || strings.HasPrefix(ename, "Wipe") || strings.HasPrefix(ename, "Update") ||
					strings.HasPrefix(ename, "Upgrade") || strings.HasPrefix(ename, "Unlink") || strings.HasPrefix(ename, "Assign") ||
					strings.HasPrefix(ename, "Unassign") || strings.HasPrefix(ename, "Suspend") || strings.HasPrefix(ename, "Set") ||
					strings.HasPrefix(ename, "Run") || strings.HasPrefix(ename, "Register") || strings.HasPrefix(ename, "Deregister") ||
					strings.HasPrefix(ename, "Reboot") || strings.HasPrefix(ename, "Purchase") || strings.HasPrefix(ename, "Modify") ||
					strings.HasPrefix(ename, "Initialize") || strings.HasPrefix(ename, "Enable") || strings.HasPrefix(ename, "Disable") ||
					strings.HasPrefix(ename, "Cancel") || strings.HasPrefix(ename, "Assign") || strings.HasPrefix(ename, "Admin") ||
					strings.HasPrefix(ename, "Activate") {
					res = "false"
				} else {
					res = "true"
				}
			} else {
				res = "false"
			}
		}
		return true, res, fsval.Offset(), fsval.Len()
	case "ct.requestid":
		fsval = jdata.Get("requestID")
	case "ct.eventtype":
		fsval = jdata.Get("eventType")
	case "ct.apiversion":
		fsval = jdata.Get("apiVersion")
	case "ct.resources":
		var resources string = ""
		fsval := jdata.Get("resources")
		if fsval == nil {
			return false, "", 0, 0
		}
		rlist, _ := fsval.Array()
		if len(rlist) == 0 {
			return false, "", 0, 0
		}
		for _, resource := range rlist {
			resources += string(resource.MarshalTo(nil))
			resources += ","
		}
		resources = strings.TrimSuffix(resources, ",")
		if resources == "" {
			return false, "", 0, 0
		}
		return true, resources, fsval.Offset(), fsval.Len()
	case "ct.recipientaccountid":
		fsval = jdata.Get("recipientAccountId")
	case "ct.serviceeventdetails":
		fsval = jdata.Get("serviceEventDetails")
	case "ct.sharedeventid":
		fsval = jdata.Get("sharedEventID")
	case "ct.vpcendpointid":
		fsval = jdata.Get("vpcEndpointId")
	case "ct.eventcategory":
		fsval = jdata.Get("eventCategory")
	case "ct.addendum.reason":
		fsval = jdata.Get("addendum", "reason")
	case "ct.addendum.updatedfields":
		fsval = jdata.Get("addendum", "updatedFields")
	case "ct.addendum.originalrequestid":
		fsval = jdata.Get("addendum", "originalRequestID")
	case "ct.addendum.originaleventid":
		fsval = jdata.Get("addendum", "originalEventID")
	case "ct.sessioncredentialfromconsole":
		fsval := jdata.Get("sessionCredentialFromConsole")
		if fsval != nil {
			res := "false"
			scc, _ := fsval.Bool()
			if scc {
				res = "true"
			}
			return true, res, fsval.Offset(), fsval.Len()
		}
	case "ct.edgedevicedetails":
		fsval = jdata.Get("edgeDeviceDetails")
	case "ct.tlsdetails.tlsversion":
		fsval = jdata.Get("tlsDetails", "tlsVersion")
	case "ct.tlsdetails.ciphersuite":
		fsval = jdata.Get("tlsDetails", "cipherSuite")
	case "ct.tlsdetails.clientprovidedhostheader":
		fsval = jdata.Get("tlsDetails", "clientProvidedHostHeader")
	case "ct.additionaleventdata":
		val := jdata.Get("additionalEventData")
		if val == nil {
			return false, "", 0, 0
		}
		return true, string(val.MarshalTo(nil)), val.Offset(), val.Len()
	case "s3.bucket":
		fsval = jdata.Get("requestParameters", "bucketName")
	case "s3.key":
		fsval = jdata.Get("requestParameters", "key")
	case "s3.uri":
		sbucket := jdata.GetStringBytes("requestParameters", "bucketName")
		if sbucket == nil {
			return false, "", 0, 0
		}

		skey := jdata.GetStringBytes("requestParameters", "key")
		if skey == nil {
			return false, "", 0, 0
		}

		res := fmt.Sprintf("s3://%s/%s", sbucket, skey)
		return true, res, 0, 0
	case "ec2.name":
		var iname string = ""
		jilist := jdata.GetArray("requestParameters", "tagSpecificationSet", "items")
		if jilist == nil {
			return false, "", 0, 0
		}
		for _, item := range jilist {
			if string(item.GetStringBytes("resourceType")) != "instance" {
				continue
			}
			tlist := item.GetArray("tags")
			for _, tag := range tlist {
				key := string(tag.GetStringBytes("key"))
				if key == "Name" {
					iname = string(tag.GetStringBytes("value"))
					break
				}
			}
		}

		if iname == "" {
			return false, "", 0, 0
		}
		return true, iname, 0, 0
	case "ec2.imageid":
		var imageId = ""
		jilist := jdata.GetArray("responseElements", "tagSpecificationSet", "items")
		if jilist == nil || len(jilist) == 0 {
			return false, "", 0, 0
		}
		item := jilist[0]
		imageId = string(item.GetStringBytes("imageId"))
		if imageId == "" {
			return false, "", 0, 0
		}
		return true, imageId, 0, 0
	case "ecr.repository":
		fsval = jdata.Get("requestParameters", "repositoryName")
	case "ecr.imagetag":
		fsval = jdata.Get("requestParameters", "imageTag")
	case "iam.role":
		fsval = jdata.Get("requestParameters", "roleName")
	case "iam.policy":
		fsval = jdata.Get("requestParameters", "policyName")
	default:
		return false, "", 0, 0
	}

	if fsval == nil {
		return false, "", 0, 0
	}

	return true, string(fsval.GetStringBytes()), fsval.Offset(), fsval.Len()
}

func getvalueU64(jvalue *fastjson.Value) uint64 {
	// Values are sometimes floats, e.g. "bytesTransferredOut": 33.0
	u64, err := jvalue.Uint64()
	if err == nil {
		return u64
	}
	f64, err := jvalue.Float64()
	if err == nil {
		return uint64(f64)
	}
	return 0
}

func getfieldU64(jdata *fastjson.Value, field string) (bool, uint64, int, int) {
	// Go should do binary search here:
	// https://github.com/golang/go/blob/8ee9bca2729ead81da6bf5a18b87767ff396d1b7/src/cmd/compile/internal/gc/swt.go#L375
	switch field {
	case "s3.bytes":
		var tot uint64 = 0
		in := jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + getvalueU64(in)
		}
		out := jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + getvalueU64(out)
		}
		return (in != nil || out != nil), tot, 0, 0
	case "s3.bytes.in":
		var tot uint64 = 0
		in := jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + getvalueU64(in)
		}
		return in != nil, tot, in.Offset(), in.Len()
	case "s3.bytes.out":
		var tot uint64 = 0
		out := jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + getvalueU64(out)
		}
		return (out != nil), tot, out.Offset(), out.Len()
	case "s3.cnt.get":
		if string(jdata.GetStringBytes("eventName")) == "GetObject" {
			return true, 1, 0, 0
		}
		return false, 0, 0, 0
	case "s3.cnt.put":
		if string(jdata.GetStringBytes("eventName")) == "PutObject" {
			return true, 1, 0, 0
		}
		return false, 0, 0, 0
	case "s3.cnt.other":
		ename := string(jdata.GetStringBytes("eventName"))
		if ename == "GetObject" || ename == "PutObject" {
			return false, 0, 0, 0
		}
		return true, 1, 0, 0
	default:
		return false, 0, 0, 0
	}
}
