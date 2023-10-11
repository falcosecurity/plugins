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

package registry

import (
	"io"
	"os"
)

// LoadRegistryFromFile loads the registry from a file on disk.
func LoadRegistryFromFile(fname string) (*Registry, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return load(file)
}

// load reads from a io.Reader and uses the content to populate and
// return a new instance of Registry
func load(r io.Reader) (*Registry, error) {
	registry := &Registry{}
	return registry, registry.Decode(r)
}
