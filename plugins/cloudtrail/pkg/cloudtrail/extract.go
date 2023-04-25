/*
Copyright (C) 2022 The Falco Authors.

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
	{Type: "string", Name: "ct.srcip", Display: "Source IP", Desc: "the IP address generating the event (sourceIPAddress in the json).", Properties: []string{"conversation"}},
	{Type: "string", Name: "ct.useragent", Display: "User Agent", Desc: "the user agent generating the event (userAgent in the json)."},
	{Type: "string", Name: "ct.info", Display: "Info", Desc: "summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details.", Properties: []string{"info"}},
	{Type: "string", Name: "ct.managementevent", Display: "Management Event", Desc: "'true' if the event is a management event (AwsApiCall, AwsConsoleAction, AwsConsoleSignIn, or AwsServiceEvent), 'false' otherwise."},
	{Type: "string", Name: "ct.readonly", Display: "Read Only", Desc: "'true' if the event only reads information (e.g. DescribeInstances), 'false' if the event modifies the state (e.g. RunInstances, CreateLoadBalancer...)."},
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
}

func getUser(jdata *fastjson.Value) (bool, string) {
	jutype := jdata.GetStringBytes("userIdentity", "type")

	if jutype == nil {
		return false, ""
	}

	utype := string(jutype)

	switch utype {
	case "Root", "IAMUser":
		jun := jdata.GetStringBytes("userIdentity", "userName")
		if jun != nil {
			return true, string(jun)
		}
	case "AWSService":
		jun := jdata.GetStringBytes("userIdentity", "invokedBy")
		if jun != nil {
			return true, string(jun)
		}
	case "AssumedRole":
		jun := jdata.GetStringBytes("userIdentity", "sessionContext", "sessionIssuer", "userName")
		if jun != nil {
			return true, string(jun)
		}
		return true, "AssumedRole"
	case "AWSAccount":
		return true, "AWSAccount"
	case "FederatedUser":
		return true, "FederatedUser"
	default:
		return false, "<unknown user type>"
	}

	return false, "<NA>"
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
	present, evtuser = getfieldStr(jdata, "ct.user")
	if !present {
		return "<invalid cloudtrail event: userIdentity field missing>"
	}

	present, evtsrcip = getfieldStr(jdata, "ct.srcip")
	if !present {
		return "<invalid cloudtrail event: eventSource field missing>"
	}

	errsymbol = ""
	present, _ = getfieldStr(jdata, "ct.error")
	if present {
		errsymbol = "!"
	}

	rwsymbol = "←"
	present, evtreadonly = getfieldStr(jdata, "ct.readonly")
	if present && evtreadonly == "false" {
		rwsymbol = "→"
	}

	present, evtname = getfieldStr(jdata, "ct.name")
	if !present {
		return "<invalid cloudtrail event: eventName field missing>"
	}

	if (evtuser == evtsrcip) {
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

	present, u64val := getfieldU64(jdata, "s3.bytes")
	if present {
		info += fmt.Sprintf(" Size=%v", u64val)
	}

	present, val := getfieldStr(jdata, "s3.uri")
	if present {
		info += fmt.Sprintf(" URI=%s", val)
		return info
	}

	present, val = getfieldStr(jdata, "s3.bucket")
	if present {
		info += fmt.Sprintf(" Bucket=%s", val)
		return info
	}

	present, val = getfieldStr(jdata, "s3.key")
	if present {
		info += fmt.Sprintf(" Key=%s", val)
		return info
	}

	present, val = getfieldStr(jdata, "ct.request.host")
	if present {
		info += fmt.Sprintf(" Host=%s", val)
		return info
	}

	return info
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	// Go should do binary search here:
	// https://github.com/golang/go/blob/8ee9bca2729ead81da6bf5a18b87767ff396d1b7/src/cmd/compile/internal/gc/swt.go#L375
	switch field {
	case "ct.id":
		val := jdata.GetStringBytes("eventID")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.error":
		val := jdata.GetStringBytes("errorCode")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.time":
		val := jdata.GetStringBytes("eventTime")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.src":
		val := jdata.GetStringBytes("eventSource")

		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.shortsrc":
		val := jdata.GetStringBytes("eventSource")

		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}

		if len(res) > len(".amazonaws.com") {
			srctrailer := res[len(res)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				res = res[0 : len(res)-len(".amazonaws.com")]
			}
		}
	case "ct.name":
		val := jdata.GetStringBytes("eventName")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.user":
		present, res := getUser(jdata)
		if !present {
			return false, ""
		}
		return true, res
	case "ct.user.accountid":
		val := jdata.GetStringBytes("userIdentity", "accountId")
		if val != nil {
			res = string(val)
		} else {
			val := jdata.GetStringBytes("recipientAccountId")
			if val != nil {
				res = string(val)
			}
			return false, ""
		}
	case "ct.user.identitytype":
		val := jdata.GetStringBytes("userIdentity", "type")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.user.principalid":
		val := jdata.GetStringBytes("userIdentity", "principalId")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.user.arn":
		val := jdata.GetStringBytes("userIdentity", "arn")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.region":
		val := jdata.GetStringBytes("awsRegion")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.response.subnetid":
		val := jdata.GetStringBytes("responseElements", "subnetId")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.response.reservationid":
		val := jdata.GetStringBytes("responseElements", "reservationId")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.availabilityzone":
		val := jdata.GetStringBytes("requestParameters", "availabilityZone")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.cluster":
		val := jdata.GetStringBytes("requestParameters", "cluster")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.functionname":
		val := jdata.GetStringBytes("requestParameters", "functionName")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.groupname":
		val := jdata.GetStringBytes("requestParameters", "groupName")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.host":
		val := jdata.GetStringBytes("requestParameters", "Host")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.name":
		val := jdata.GetStringBytes("requestParameters", "name")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.policy":
		val := jdata.GetStringBytes("requestParameters", "policy")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.serialnumber":
		val := jdata.GetStringBytes("requestParameters", "serialNumber")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.servicename":
		val := jdata.GetStringBytes("requestParameters", "serviceName")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.subnetid":
		val := jdata.GetStringBytes("requestParameters", "subnetId")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.taskdefinition":
		val := jdata.GetStringBytes("requestParameters", "taskDefinition")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.request.username":
		val := jdata.GetStringBytes("requestParameters", "userName")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.srcip":
		val := jdata.GetStringBytes("sourceIPAddress")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.useragent":
		val := jdata.GetStringBytes("userAgent")
		if val == nil {
			return false, ""
		} else {
			res = string(val)
		}
	case "ct.info":
		res = getEvtInfo(jdata)
	case "ct.managementevent":
		ro := jdata.GetBool("managementEvent")
		if ro {
			res = "true"
		} else {
			res = "false"
		}
	case "ct.readonly":
		ro := jdata.GetBool("readOnly")
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
					return false, ""
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
	case "s3.bucket":
		val := jdata.GetStringBytes("requestParameters", "bucketName")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "s3.key":
		val := jdata.GetStringBytes("requestParameters", "key")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "s3.uri":
		sbucket := jdata.GetStringBytes("requestParameters", "bucketName")
		if sbucket == nil {
			return false, ""
		}
		skey := jdata.GetStringBytes("requestParameters", "key")
		if skey == nil {
			return false, ""
		}
		res = fmt.Sprintf("s3://%s/%s", sbucket, skey)
	case "ec2.name":
		var iname string = ""
		jilist := jdata.GetArray("requestParameters", "tagSpecificationSet", "items")
		if jilist == nil {
			return false, ""
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
			return false, ""
		}
		res = iname
	case "ec2.imageid":
		var imageId = ""
		jilist := jdata.GetArray("responseElements", "tagSpecificationSet", "items")
		if jilist == nil || len(jilist) == 0 {
			return false, ""
		}
		item := jilist[0]
		imageId = string(item.GetStringBytes("imageId"))
		if imageId == "" {
			return false, ""
		}
		res = imageId
	case "ecr.repository":
		val := jdata.GetStringBytes("requestParameters", "repositoryName")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "ecr.imagetag":
		val := jdata.GetStringBytes("requestParameters", "imageTag")
		if val == nil {
			return false, ""
		}
		res = string(val)
	default:
		return false, ""
	}

	return true, res
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

func getfieldU64(jdata *fastjson.Value, field string) (bool, uint64) {
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
		return (in != nil || out != nil), tot
	case "s3.bytes.in":
		var tot uint64 = 0
		in := jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + getvalueU64(in)
		}
		return (in != nil), tot
	case "s3.bytes.out":
		var tot uint64 = 0
		out := jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + getvalueU64(out)
		}
		return (out != nil), tot
	case "s3.cnt.get":
		if string(jdata.GetStringBytes("eventName")) == "GetObject" {
			return true, 1
		}
		return false, 0
	case "s3.cnt.put":
		if string(jdata.GetStringBytes("eventName")) == "PutObject" {
			return true, 1
		}
		return false, 0
	case "s3.cnt.other":
		ename := string(jdata.GetStringBytes("eventName"))
		if ename == "GetObject" || ename == "PutObject" {
			return true, 1
		}
		return false, 0
	default:
		return false, 0
	}
}
