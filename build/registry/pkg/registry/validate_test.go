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

package registry

import "testing"

func TestValidateRejectsPathTraversal(t *testing.T) {
	cases := []struct {
		name    string
		plugin  string
		wantErr bool
	}{
		{"valid name", "myplugin", false},
		{"valid with digits", "plugin01", false},
		{"valid with hyphen", "my-plugin", false},
		{"valid with underscore", "my_plugin", false},
		{"path traversal parent", "../target", true},
		{"path traversal nested", "../../etc", true},
		{"absolute path", "/tmp/evil", true},
		{"dot prefix", ".hidden", true},
		{"contains slash", "a/b", true},
		{"empty name", "", true},
		{"uppercase", "MyPlugin", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Registry{
				Plugins: []Plugin{{
					Name:    tc.plugin,
					Authors: "test",
					Capabilities: Capabilities{
						Sourcing: SourcingCapability{Supported: false},
					},
				}},
			}
			err := r.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate() should have rejected name %q", tc.plugin)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() should have accepted name %q, got: %v", tc.plugin, err)
			}
		})
	}
}
