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

package extractor

import (
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

func Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	data, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}

	jdata, err := fastjson.Parse(string(data))
	if err != nil {
		// Not a json file, so not present.
		return err
	}

	// Extract the field value
	var present bool
	var value interface{}
	if req.FieldType() == sdk.ParamTypeUint64 {
		present, value = getfieldU64(jdata, req.Field())
	} else {
		present, value = getfieldStr(jdata, req.Field())
	}
	if present {
		req.SetValue(value)
	}

	return nil
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var val []byte

	switch field {
	case "ka.auditid":
		val = jdata.GetStringBytes("auditID")
	case "ka.stage":
		val = jdata.GetStringBytes("stage")
	case "ka.auth.decision":
		val = jdata.GetStringBytes("annotations", "authorization.k8s.io/decision")
	case "ka.auth.reason":
		val = jdata.GetStringBytes("annotations", "authorization.k8s.io/reason")
	case "ka.user.name":
		val = jdata.GetStringBytes("user", "username")
	case "ka.user.groups":
		val = jdata.GetStringBytes("user", "groups")
	case "ka.impuser.name":
		val = jdata.GetStringBytes("impersonatedUser", "username")
	case "ka.verb":
		val = jdata.GetStringBytes("verb")
	case "ka.uri":
		val = jdata.GetStringBytes("requestURI")
	case "ka.uri.param":
		// todo
		// https://github.com/falcosecurity/libs/pull/201
		// https://github.com/falcosecurity/libs/pull/206
		// https://github.com/falcosecurity/plugin-sdk-go/pull/42
		// https://github.com/falcosecurity/plugin-sdk-go/pull/44
	case "ka.target.name":
		val = jdata.GetStringBytes("objectRef", "name")
	case "ka.target.namespace":
		val = jdata.GetStringBytes("objectRef", "namespace")
	case "ka.target.resource":
		val = jdata.GetStringBytes("objectRef", "resource")
	case "ka.target.subresource":
		val = jdata.GetStringBytes("objectRef", "subresource")
	case "ka.req.binding.subjects":
		val = jdata.GetStringBytes("requestObject", "subjects")
	case "ka.req.binding.role":
		val = jdata.GetStringBytes("requestObject", "roleRef", "name")
	case "ka.req.binding.subject.has_name":
		val = []byte("N/A")
	case "ka.req.configmap.name":
		val = jdata.GetStringBytes("objectRef", "name")
	case "ka.req.configmap.obj":
		val = jdata.GetStringBytes("requestObject", "data")
	case "ka.req.pod.containers.image":
		// todo
		// https://github.com/falcosecurity/libs/pull/201
		// https://github.com/falcosecurity/libs/pull/206
		// https://github.com/falcosecurity/plugin-sdk-go/pull/42
		// https://github.com/falcosecurity/plugin-sdk-go/pull/44
	case "ka.req.pod.containers.image.repository":
		// todo
		// https://github.com/falcosecurity/libs/pull/201
		// https://github.com/falcosecurity/libs/pull/206
		// https://github.com/falcosecurity/plugin-sdk-go/pull/42
		// https://github.com/falcosecurity/plugin-sdk-go/pull/44
	case "ka.req.container.image":
		val = extractImage(jdata)[0]
	case "ka.req.container.image.repository":
		val = extractRepository(jdata)[0]
	case "ka.req.pod.host_ipc":
		val = jdata.GetStringBytes("requestObject", "spec", "hostIPC")
	case "ka.req.pod.host_network":
		val = jdata.GetStringBytes("requestObject", "spec", "hostNetwork")
	case "ka.req.container.host_network":
		val = jdata.GetStringBytes("requestObject", "spec", "hostNetwork")
	case "ka.req.pod.host_pid":
		val = jdata.GetStringBytes("requestObject", "spec", "hostPID")
	case "ka.req.pod.containers.host_port":
		// todo
	case "ka.req.pod.containers.privileged":
		// todo
	case "ka.req.container.privileged":
		val = []byte("false")
		for _, i := range extractSecurityContextBool(jdata, "privileged") {
			if string(i) == "true" {
				val = []byte("true")
			}
		}
	case "ka.req.pod.containers.allow_privilege_escalation":
		// todo
	case "ka.req.pod.containers.read_only_fs":
		// todo
	case "ka.req.pod.run_as_user":
		val = jdata.GetStringBytes("requestObject", "spec", "securityContext", "runAsUser")
	case "ka.req.pod.containers.run_as_user":
		// todo
	case "ka.req.pod.containers.eff_run_as_user":
		// todo
	case "ka.req.pod.run_as_group":
		val = jdata.GetStringBytes("requestObject", "spec", "securityContext", "runAsGroup")
	case "ka.req.pod.containers.run_as_group":
		// todo
	case "ka.req.pod.containers.eff_run_as_group":
		// todo
	case "ka.req.pod.containers.proc_mount":
		// todo
	case "ka.req.role.rules":
		val = jdata.GetStringBytes("requestObject", "rules")
	case "ka.req.role.rules.apiGroups":
		// todo
	case "ka.req.role.rules.nonResourceURLs":
		// todo
	case "ka.req.role.rules.verbs":
		// todo
	case "ka.req.role.rules.resources":
		// todo
	case "ka.req.pod.fs_group":
		val = jdata.GetStringBytes("requestObject", "spec", "securityContext", "fsGroup")
	case "ka.req.pod.supplemental_groups":
		// todo
	case "ka.req.pod.containers.add_capabilities":
		// todo
	case "ka.req.service.type":
		val = jdata.GetStringBytes("requestObject", "spec", "type")
	case "ka.req.service.ports":
		val = jdata.GetStringBytes("requestObject", "spec", "ports")
	case "ka.req.volume.hostpath":
		// todo
	case "ka.req.pod.volumes.hostpath":
		// todo
	case "ka.req.pod.volumes.flexvolume_driver":
		// todo
	case "ka.req.pod.volumes.volume_type":
		// todo
	case "ka.resp.name":
		val = jdata.GetStringBytes("responseObject", "metadata", "name")
	case "ka.response.reason":
		val = jdata.GetStringBytes("responseStatus", "reason")
	case "ka.useragent":
		val = jdata.GetStringBytes("userAgent")
	default:
		return false, ""
	}

	if val != nil {
		return true, string(val)
	}
	return false, ""
}

func getfieldU64(jdata *fastjson.Value, field string) (bool, uint64) {
	switch field {
	case "ka.response.code":
		val := jdata.Get("responseStatus", "code")
		if val != nil {
			return true, val.GetUint64()
		}
		return false, 0
	default:
		return false, 0
	}
}

func extractImage(jdata *fastjson.Value) (images [][]byte) {
	switch string(jdata.GetStringBytes("objectRef", "resource")) {
	case "daemonsets", "deployment":
		containers := jdata.Get("requestObject", "spec", "template", "spec").GetArray("containers")
		for _, i := range containers {
			images = append(images, i.GetStringBytes("image"))
		}
	case "pod":
		containers := jdata.Get("requestObject", "spec").GetArray("containers")
		for _, i := range containers {
			images = append(images, i.GetStringBytes("image"))
		}
	}
	return
}

func extractRepository(jdata *fastjson.Value) (repositories [][]byte) {
	images := extractImage(jdata)
	for _, i := range images {
		repository := []byte(strings.Join(strings.Split(string(i), "/")[1:], "/"))
		repositories = append(repositories, repository)
	}
	return
}

func extractSecurityContextBool(jdata *fastjson.Value, field string) (output map[string][]byte) {
	output = make(map[string][]byte)
	if string(jdata.GetStringBytes("objectRef", "resource")) == "pod" {
		containers := jdata.Get("requestObject", "spec").GetArray("containers")
		for _, i := range containers {
			output[string(i.GetStringBytes("image"))] = []byte(strconv.FormatBool(i.GetBool("securityContext", field)))
		}
	}
	return
}
