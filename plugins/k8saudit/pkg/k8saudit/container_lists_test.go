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
	"fmt"
	"strings"
	"testing"

	"github.com/valyala/fastjson"
)

// capturingRequest records the value the extractor sets, reusing testExtractRequest
// for the rest of the sdk.ExtractRequest interface.
type capturingRequest struct {
	testExtractRequest
	captured interface{}
}

func (c *capturingRequest) SetValue(v interface{}) { c.captured = v }

func Test_ContainerListFieldsAreSeparate(t *testing.T) {
	e := &Plugin{}

	extract := func(field, raw string) string {
		v, err := fastjson.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		req := &capturingRequest{testExtractRequest: testExtractRequest{field: field, isList: true}}
		if err := e.ExtractFromJSON(req, v); err != nil {
			t.Fatalf("extract error: %v", err)
		}
		return fmt.Sprintf("%v", req.captured)
	}

	pod := `{"auditID":"a","requestObject":{"spec":{` +
		`"containers":[{"name":"c","image":"reg.example.com/c:1","securityContext":{"privileged":false}}],` +
		`"initContainers":[{"name":"i","image":"reg.example.com/i:1","securityContext":{"privileged":true}}],` +
		`"ephemeralContainers":[{"name":"e","image":"reg.example.com/e:1","securityContext":{"privileged":true}}]}}}`

	// ka.req.pod.containers.* must not reach into init or ephemeral containers.
	if got := extract("ka.req.pod.containers.privileged", pod); strings.Contains(got, "true") {
		t.Errorf("containers.privileged leaked init/ephemeral: got %q", got)
	}
	if got := extract("ka.req.pod.containers.image", pod); strings.Contains(got, "reg.example.com/i:1") {
		t.Errorf("containers.image leaked init image: got %q", got)
	}

	// The init and ephemeral lists expose their own securityContext and images.
	if got := extract("ka.req.pod.initContainers.privileged", pod); !strings.Contains(got, "true") {
		t.Errorf("initContainers.privileged not extracted: got %q", got)
	}
	if got := extract("ka.req.pod.ephemeralContainers.privileged", pod); !strings.Contains(got, "true") {
		t.Errorf("ephemeralContainers.privileged not extracted: got %q", got)
	}
	if got := extract("ka.req.pod.initContainers.image", pod); !strings.Contains(got, "reg.example.com/i:1") {
		t.Errorf("initContainers.image not extracted: got %q", got)
	}
}
