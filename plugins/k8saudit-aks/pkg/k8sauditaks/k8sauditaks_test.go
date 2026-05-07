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

package k8sauditaks

import "testing"

func TestIsValidJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"whitespace only", "   \n\t", false},
		{"object", `{"kind":"Event"}`, true},
		{"array", `[{"kind":"Event"}]`, true},
		{"object with leading whitespace", "  \n\t{\"kind\":\"Event\"}", true},
		{"klog info line", `I0109 21:24:54.475483       1 clusterstate.go:300] Failed to find readiness information for node`, false},
		{"klog trace line", `Trace[7816759]: ---"limitedReadBody succeeded" len:629048 11ms (21:25:16.354)`, false},
		{"plain text", "some random log line", false},
		{"truncated object", `{"kind":"Event"`, false},
		{"utf8 bom prefix", "\xef\xbb\xbf{\"kind\":\"Event\"}", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidJSON([]byte(tc.in)); got != tc.want {
				t.Errorf("isValidJSON(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
