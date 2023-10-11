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

package distribution_test

import (
	"reflect"
	"testing"

	"github.com/falcosecurity/falcoctl/pkg/index/index"

	"github.com/falcosecurity/plugins/build/registry/pkg/distribution"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
)

func TestPluginToIndexEntrySignature(t *testing.T) {
	t.Parallel()

	signature := &index.Signature{
		Cosign: &index.CosignSignature{},
	}

	expected := signature

	p := registry.Plugin{Signature: signature}

	entry := distribution.PluginToIndexEntry(p, "", "")
	if !reflect.DeepEqual(entry.Signature, expected) {
		t.Fatalf("Index entry signature: expected %#v, got %v", expected, entry.Signature)
	}
}

func TestPluginRulesToIndexEntrySignature(t *testing.T) {
	t.Parallel()

	signature := &index.Signature{
		Cosign: &index.CosignSignature{},
	}

	expected := signature

	p := registry.Plugin{Signature: signature}

	entry := distribution.PluginRulesToIndexEntry(p, "", "")
	if !reflect.DeepEqual(entry.Signature, expected) {
		t.Fatalf("Index entry signature: expected %#v, got %v", expected, entry.Signature)
	}
}
