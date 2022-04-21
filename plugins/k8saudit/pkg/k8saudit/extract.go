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

package k8saudit

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

const (
	noIndexFilter = -1
)

var (
	// ErrExtractNotAvailable indicates that the requested field cannot be
	// extracted from a certain event due to some value not being available
	// inside the event.
	ErrExtractNotAvailable = fmt.Errorf("field not available")
	//
	// ErrExtractWrongType indicates that the requested field cannot be
	// extracted from a certain event due to some value having an unexpected
	// type inside the event.
	ErrExtractWrongType = fmt.Errorf("wrong type conversion")
	//
	// ErrExtractBrokenJSON indicates that the requested field cannot be
	// extracted from a certain event due to the internal JSON prepresentaiton
	// being broken or badly formatted
	ErrExtractBrokenJSON = fmt.Errorf("broken JSON data")
	//
	// ErrExtractUnsupportedType indicates that the requested field cannot be
	// extracted from a certain event due to its field type being not supported
	ErrExtractUnsupportedType = fmt.Errorf("type not supported")
)

// AuditEventExtractor is an helper that extract K8S Audit fields from
// K8S Audit events. The event data is expected to be a JSON that in the form
// that is provided by K8S Audit webhook (see https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#webhook-backend).
// The ExtractFromEvent method can be used to easily process an ExtractRequest.
// If the Audit Event data is nested inside another JSON object, you can use
// a combination of the Decode/DecodeEvent and ExtractFromJSON convenience
// methods. AuditEventExtractor relies on the fastjson package for performant
// manipulation of JSON data.
type AuditEventExtractor struct {
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64
}

// Decode parses a JSON value from a io.Reader
func (e *AuditEventExtractor) Decode(evtNum uint64, reader io.ReadSeeker) (*fastjson.Value, error) {
	// as a very quick sanity check, only try to extract all if
	// the first character is '{' or '['
	data := []byte{0}
	_, err := reader.Read(data)
	if err != nil {
		return nil, err
	}
	if !(data[0] == '{' || data[0] == '[') {
		return nil, ErrExtractBrokenJSON
	}
	// decode the json, but only if we haven't done it yet for this event
	if evtNum != e.jdataEvtnum {
		_, err := reader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		data, err = ioutil.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		e.jdata, err = e.jparser.ParseBytes(data)
		if err != nil {
			return nil, err
		}
		e.jdataEvtnum = evtNum
	}
	return e.jdata, nil
}

// DecodeEvent parses a JSON value from a sdk.EventReader
func (e *AuditEventExtractor) DecodeEvent(evt sdk.EventReader) (*fastjson.Value, error) {
	return e.Decode(evt.EventNum(), evt.Reader())
}

// ExtractFromEvent processes a sdk.ExtractRequest and extracts a
// field by reading data from a sdk.EventReader
func (e *AuditEventExtractor) ExtractFromEvent(req sdk.ExtractRequest, evt sdk.EventReader) error {
	jsonValue, err := e.DecodeEvent(evt)
	if err != nil {
		return err
	}
	return e.ExtractFromJSON(req, jsonValue)
}

// ExtractFromJSON processes a sdk.ExtractRequest and extracts a
// field by reading data from a jsonValue *fastjson.Value
func (e *AuditEventExtractor) ExtractFromJSON(req sdk.ExtractRequest, jsonValue *fastjson.Value) error {
	// discard unrelated JSONs events
	if jsonValue.Get("auditID") == nil {
		return ErrExtractNotAvailable
	}
	switch req.Field() {
	case "ka.auditid":
		return e.extractFromKeys(req, jsonValue, "auditID")
	case "ka.stage":
		return e.extractFromKeys(req, jsonValue, "stage")
	case "ka.auth.decision":
		return e.extractFromKeys(req, jsonValue, "annotations", "authorization.k8s.io/decision")
	case "ka.auth.reason":
		return e.extractFromKeys(req, jsonValue, "annotations", "authorization.k8s.io/reason")
	case "ka.user.name":
		return e.extractFromKeys(req, jsonValue, "user", "username")
	case "ka.user.groups":
		return e.extractFromKeys(req, jsonValue, "user", "groups")
	case "ka.impuser.name":
		return e.extractFromKeys(req, jsonValue, "impersonatedUser", "username")
	case "ka.verb":
		return e.extractFromKeys(req, jsonValue, "verb")
	case "ka.uri":
		return e.extractFromKeys(req, jsonValue, "requestURI")
	case "ka.uri.param":
		uriValue := jsonValue.Get("requestURI")
		if uriValue == nil {
			return ErrExtractNotAvailable
		}
		uriString, err := e.jsonValueAsString(uriValue)
		if err != nil {
			return err
		}
		uri, err := url.Parse(uriString)
		if err != nil {
			return err
		}
		query, err := url.ParseQuery(uri.RawQuery)
		if err != nil {
			return err
		}
		param := query[req.ArgKey()]
		if len(param) > 0 {
			req.SetValue(param[0])
		}
	case "ka.target.name":
		return e.extractFromKeys(req, jsonValue, "objectRef", "name")
	case "ka.target.namespace":
		return e.extractFromKeys(req, jsonValue, "objectRef", "namespace")
	case "ka.target.resource":
		return e.extractFromKeys(req, jsonValue, "objectRef", "resource")
	case "ka.target.subresource":
		return e.extractFromKeys(req, jsonValue, "objectRef", "subresource")
	case "ka.req.binding.subjects":
		return e.extractFromKeys(req, jsonValue, "requestObject", "subjects")
	case "ka.req.binding.role":
		return e.extractFromKeys(req, jsonValue, "requestObject", "roleRef", "name")
	case "ka.req.binding.subject.has_name":
		// note(jasondellaluce): this is documented to return N/A, however
		// the original K8S Audit implementation returns true here
		req.SetValue("true")
	case "ka.req.configmap.name":
		return e.extractFromKeys(req, jsonValue, "objectRef", "name")
	case "ka.req.configmap.obj":
		return e.extractFromKeys(req, jsonValue, "requestObject", "data")
	case "ka.req.pod.containers.image":
		indexFilter := e.argIndexFilter(req)
		images, err := e.readContainerImages(jsonValue, indexFilter)
		if err != nil {
			return err
		}
		req.SetValue(images)
	case "ka.req.pod.containers.image.repository":
		indexFilter := e.argIndexFilter(req)
		repos, err := e.readContainerRepositories(jsonValue, indexFilter)
		if err != nil {
			return err
		}
		req.SetValue(repos)
	case "ka.req.container.image":
		images, err := e.readContainerImages(jsonValue, 0)
		if err != nil {
			return err
		}
		req.SetValue(images[0])
	case "ka.req.container.image.repository":
		repos, err := e.readContainerRepositories(jsonValue, 0)
		if err != nil {
			return err
		}
		req.SetValue(repos[0])
	case "ka.req.pod.host_ipc":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "hostIPC")
	case "ka.req.pod.host_network":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "hostNetwork")
	case "ka.req.container.host_network":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "hostNetwork")
	case "ka.req.pod.host_pid":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "hostPID")
	case "ka.req.pod.containers.host_port":
		indexFilter := e.argIndexFilter(req)
		values, err := e.readContainerHostPorts(jsonValue, indexFilter)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.containers.privileged":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "securityContext", "privileged")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStringsSkipNil(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.container.privileged":
		privileged, err := e.readAnyContainerPrivileged(jsonValue, noIndexFilter)
		if err != nil {
			return err
		}
		req.SetValue(privileged)
	case "ka.req.pod.containers.allow_privilege_escalation":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "securityContext", "allowPrivilegeEscalation")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.containers.read_only_fs":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "securityContext", "readOnlyRootFilesystem")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.run_as_user":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "securityContext", "runAsUser")
	case "ka.req.pod.containers.run_as_user":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "securityContext", "runAsUser")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.containers.eff_run_as_user":
		indexFilter := e.argIndexFilter(req)
		values, err := e.readFromContainerEffectively(jsonValue, indexFilter, "runAsUser")
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.run_as_group":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "securityContext", "runAsGroup")
	case "ka.req.pod.containers.run_as_group":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "securityContext", "runAsGroup")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.containers.eff_run_as_group":
		indexFilter := e.argIndexFilter(req)
		values, err := e.readFromContainerEffectively(jsonValue, indexFilter, "runAsGroup")
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.containers.proc_mount":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "securityContext", "procMount")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.role.rules":
		return e.extractFromKeys(req, jsonValue, "requestObject", "rules")
	case "ka.req.role.rules.apiGroups":
		return e.extractRulesField(req, jsonValue, "apiGroups")
	case "ka.req.role.rules.nonResourceURLs":
		return e.extractRulesField(req, jsonValue, "nonResourceURLs")
	case "ka.req.role.rules.verbs":
		return e.extractRulesField(req, jsonValue, "verbs")
	case "ka.req.role.rules.resources":
		return e.extractRulesField(req, jsonValue, "resources")
	case "ka.req.pod.fs_group":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "securityContext", "fsGroup")
	case "ka.req.pod.supplemental_groups":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "securityContext", "supplementalGroups")
	case "ka.req.pod.containers.add_capabilities":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "securityContext", "capabilities", "add")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.service.type":
		return e.extractFromKeys(req, jsonValue, "requestObject", "spec", "type")
	case "ka.req.service.ports":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "ports")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.volume.hostpath":
		arg := req.ArgKey()
		arr, err := e.getArray(jsonValue, noIndexFilter, "requestObject", "spec", "volumes")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "hostPath", "path")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}

		// if the index key ends with a *, do a prefix match.
		// Otherwise, compare for equality.
		isPrefixSearch := strings.HasSuffix(arg, "*")
		prefixSearch := arg[:len(arg)-1]
		for _, v := range values {
			if isPrefixSearch && strings.HasPrefix(v, prefixSearch) || arg == v {
				req.SetValue("true")
				return nil
			}
		}
		req.SetValue("false")
	case "ka.req.pod.volumes.hostpath":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "volumes")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "hostPath", "path")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.volumes.flexvolume_driver":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "volumes")
		if err != nil {
			return err
		}
		arr, err = e.getFlatArray(arr, false, "flexVolume", "driver")
		if err != nil {
			return err
		}
		values, err := e.arrayAsStrings(arr)
		if err != nil {
			return err
		}
		req.SetValue(values)
	case "ka.req.pod.volumes.volume_type":
		indexFilter := e.argIndexFilter(req)
		arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "volumes")
		if err != nil {
			return err
		}
		var values []string
		// note(jasondellaluce): this has been implemented just like in the
		// original K8S Audit, but I'm not sure this works as intended
		for _, v := range arr {
			obj, err := v.Object()
			if err != nil {
				return err
			}
			obj.Visit(func(key []byte, v *fastjson.Value) {
				if string(key) != "name" {
					values = append(values, string(key))
				}
			})
		}
		req.SetValue(values)
	case "ka.resp.name":
		return e.extractFromKeys(req, jsonValue, "responseObject", "metadata", "name")
	case "ka.response.code":
		return e.extractFromKeys(req, jsonValue, "responseStatus", "code")
	case "ka.response.reason":
		return e.extractFromKeys(req, jsonValue, "responseStatus", "reason")
	case "ka.useragent":
		return e.extractFromKeys(req, jsonValue, "userAgent")
	default:
		return fmt.Errorf("unsupported extraction field: %s", req.Field())
	}
	return nil
}

func (e *AuditEventExtractor) argIndexFilter(req sdk.ExtractRequest) int {
	if !req.ArgPresent() {
		return noIndexFilter
	}
	return int(req.ArgIndex())
}

func (e *AuditEventExtractor) getArray(jsonValue *fastjson.Value, indexFilter int, keys ...string) ([]*fastjson.Value, error) {
	arr := jsonValue.GetArray(keys...)
	if arr == nil {
		return nil, ErrExtractNotAvailable
	}
	if indexFilter != noIndexFilter {
		if indexFilter < 0 || indexFilter >= len(arr) {
			return nil, ErrExtractNotAvailable
		}
		return []*fastjson.Value{arr[indexFilter]}, nil
	}
	return arr, nil
}

func (e *AuditEventExtractor) getFlatArray(arr []*fastjson.Value, allowNil bool, keys ...string) ([]*fastjson.Value, error) {
	var res []*fastjson.Value
	for _, v := range arr {
		value := v.Get(keys...)
		if value == nil && !allowNil {
			return nil, ErrExtractNotAvailable
		}
		res = append(res, value)
	}
	return res, nil
}

func (e *AuditEventExtractor) arrayAsStrings(values []*fastjson.Value) ([]string, error) {
	var res []string
	for _, v := range values {
		str, err := e.jsonValueAsString(v)
		if err != nil {
			return nil, err
		}
		res = append(res, str)
	}
	return res, nil
}

func (e *AuditEventExtractor) arrayAsStringsSkipNil(values []*fastjson.Value) ([]string, error) {
	var res []string
	for _, v := range values {
		if v != nil {
			str, err := e.jsonValueAsString(v)
			if err != nil {
				return nil, err
			}
			res = append(res, str)
		}
	}
	return res, nil
}

func (e *AuditEventExtractor) arrayAsStringsWithDefault(values []*fastjson.Value, defaultValue string) ([]string, error) {
	var res []string
	for _, v := range values {
		str, err := e.jsonValueAsString(v)
		if err != nil {
			str = defaultValue
		}
		res = append(res, str)
	}
	return res, nil
}

func (e *AuditEventExtractor) readContainerImages(jsonValue *fastjson.Value, indexFilter int) ([]string, error) {
	arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
	if err != nil {
		return nil, err
	}
	arr, err = e.getFlatArray(arr, false, "image")
	if err != nil {
		return nil, err
	}
	return e.arrayAsStrings(arr)
}

func (e *AuditEventExtractor) readContainerRepositories(jsonValue *fastjson.Value, indexFilter int) ([]string, error) {
	images, err := e.readContainerImages(jsonValue, indexFilter)
	if err != nil {
		return nil, err
	}
	var repos []string
	for _, image := range images {
		repos = append(repos, strings.Split(strings.Split(image, ":")[0], "@")[0])
	}
	return repos, nil
}

func (e *AuditEventExtractor) readContainerHostPorts(jsonValue *fastjson.Value, indexFilter int) ([]string, error) {
	arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
	if err != nil {
		return nil, err
	}
	containersPorts, err := e.getFlatArray(arr, false, "ports")
	if err != nil {
		return nil, err
	}
	var res []string
	for _, ports := range containersPorts {
		if ports.Type() != fastjson.TypeArray {
			return nil, ErrExtractWrongType
		}
		for _, port := range ports.GetArray() {
			if port.Get("hostPort") != nil {
				p, err := e.jsonValueAsString(port.Get("hostPort"))
				if err != nil {
					return nil, err
				}
				res = append(res, p)
			} else if port.Get("containerPort") != nil {
				// when hostNetwork is true, this will match the host port
				p, err := e.jsonValueAsString(port.Get("containerPort"))
				if err != nil {
					return nil, err
				}
				res = append(res, p)
			}
		}
	}
	return res, nil
}

func (e *AuditEventExtractor) readAnyContainerPrivileged(jsonValue *fastjson.Value, indexFilter int) (string, error) {
	arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
	if err != nil {
		return "", err
	}
	privileged, err := e.getFlatArray(arr, false, "securityContext", "privileged")
	if err != nil {
		return "", err
	}
	for _, priv := range privileged {
		if priv.GetBool() {
			return "true", nil
		}
	}
	return "false", nil
}

func (e *AuditEventExtractor) readFromContainerEffectively(jsonValue *fastjson.Value, indexFilter int, keys ...string) ([]string, error) {
	podID := "0"
	if value := jsonValue.Get(append([]string{"requestObject", "spec"}, keys...)...); value != nil {
		var err error
		podID, err = e.jsonValueAsString(value)
		if err != nil {
			return nil, err
		}
	}
	arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "spec", "containers")
	if err != nil {
		return nil, err
	}
	arr, err = e.getFlatArray(arr, true, keys...)
	if err != nil {
		return nil, err
	}
	return e.arrayAsStringsWithDefault(arr, podID)
}

func (e *AuditEventExtractor) extractRulesField(req sdk.ExtractRequest, jsonValue *fastjson.Value, keys ...string) error {
	indexFilter := e.argIndexFilter(req)
	arr, err := e.getArray(jsonValue, indexFilter, "requestObject", "rules")
	if err != nil {
		return err
	}
	arr, err = e.getFlatArray(arr, true, keys...)
	if err != nil {
		return err
	}
	var values []string
	for _, v := range arr {
		if v != nil && v.Type() == fastjson.TypeArray {
			strs, err := e.arrayAsStringsSkipNil(v.GetArray())
			if err != nil {
				return err
			}
			values = append(values, strs...)
		}
	}
	req.SetValue(values)
	return nil
}

func (e *AuditEventExtractor) extractFromKeys(req sdk.ExtractRequest, jsonValue *fastjson.Value, keys ...string) error {
	jsonValue = jsonValue.Get(keys...)
	if jsonValue == nil {
		return ErrExtractNotAvailable
	}
	if req.IsList() {
		if jsonValue.Type() != fastjson.TypeArray {
			return ErrExtractWrongType
		}
		switch req.FieldType() {
		case sdk.FieldTypeCharBuf:
			var res []string
			for _, v := range jsonValue.GetArray() {
				val, err := e.jsonValueAsString(v)
				if err != nil {
					return err
				}
				res = append(res, val)
			}
			req.SetValue(res)
		default:
			return ErrExtractUnsupportedType
		}
	} else {
		switch req.FieldType() {
		case sdk.FieldTypeCharBuf:
			val, err := e.jsonValueAsString(jsonValue)
			if err != nil {
				return err
			}
			req.SetValue(val)
		default:
			return ErrExtractUnsupportedType
		}
	}
	return nil
}

func (e *AuditEventExtractor) jsonValueAsString(v *fastjson.Value) (string, error) {
	if v != nil {
		if v.Type() == fastjson.TypeString {
			return string(v.GetStringBytes()), nil
		}
		return string(string(v.MarshalTo(nil))), nil
	}
	return "", ErrExtractWrongType
}
