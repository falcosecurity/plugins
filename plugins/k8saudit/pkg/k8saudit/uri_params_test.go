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

package k8saudit

import (
	"reflect"
	"testing"

	"github.com/valyala/fastjson"
)

func Test_URIParamFields(t *testing.T) {
	e := &Plugin{}

	extract := func(t *testing.T, field string, isList bool, key, uri string) interface{} {
		t.Helper()
		v, err := fastjson.Parse(`{"auditID":"a","requestURI":` + fastjson.MustParse(`"`+uri+`"`).String() + `}`)
		if err != nil {
			t.Fatal(err)
		}
		req := &capturingRequest{testExtractRequest: testExtractRequest{field: field, isList: isList, argPresent: true, argKey: key}}
		if err := e.ExtractFromJSON(req, v); err != nil {
			t.Fatalf("extract %s[%s] error: %v", field, key, err)
		}
		return req.captured
	}

	// kubectl exec -it pod-0 -- cat /etc/os-release "a b"
	exec := "/api/v1/namespaces/ns/pods/pod-0/exec?command=cat&command=%2Fetc%2Fos-release&command=a+b&container=c&stdin=true"

	tests := []struct {
		name   string
		field  string
		isList bool
		key    string
		uri    string
		want   interface{}
	}{
		{"params keeps every repeated value in order, decoded", "ka.uri.params", true, "command", exec, []string{"cat", "/etc/os-release", "a b"}},
		{"params with a single value", "ka.uri.params", true, "container", exec, []string{"c"}},
		{"params with a missing key sets nothing", "ka.uri.params", true, "tty", exec, nil},
		{"params on a uri without a query sets nothing", "ka.uri.params", true, "command", "/api/v1/pods", nil},
		{"params with an empty value", "ka.uri.params", true, "command", "/exec?command=", []string{""}},
		{"param still returns only the first value", "ka.uri.param", false, "command", exec, "cat"},
		{"param decodes the value", "ka.uri.param", false, "command", "/exec?command=%2Fbin%2Fsh", "/bin/sh"},
		{"param with a missing key sets nothing", "ka.uri.param", false, "tty", exec, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extract(t, tt.field, tt.isList, tt.key, tt.uri)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%s[%s] = %#v, want %#v", tt.field, tt.key, got, tt.want)
			}
		})
	}
}

func Test_URIParamFieldsWithoutRequestURI(t *testing.T) {
	e := &Plugin{}
	v := fastjson.MustParse(`{"auditID":"a"}`)
	for _, field := range []string{"ka.uri.param", "ka.uri.params"} {
		req := &capturingRequest{testExtractRequest: testExtractRequest{field: field, isList: field == "ka.uri.params", argPresent: true, argKey: "command"}}
		if err := e.ExtractFromJSON(req, v); err != ErrExtractNotAvailable {
			t.Errorf("%s without requestURI: got error %v, want ErrExtractNotAvailable", field, err)
		}
	}
}

func Test_URIParamsFieldDefinition(t *testing.T) {
	e := &Plugin{}
	for _, f := range e.Fields() {
		if f.Name != "ka.uri.params" {
			continue
		}
		if f.Type != "string" || !f.IsList || !f.Arg.IsKey || !f.Arg.IsRequired {
			t.Fatalf("unexpected ka.uri.params definition: %+v", f)
		}
		return
	}
	t.Fatal("ka.uri.params is not defined")
}
