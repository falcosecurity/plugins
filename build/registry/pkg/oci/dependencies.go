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

package oci

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"gopkg.in/yaml.v3"
)

const depsKey = "- required_plugin_versions"

// ErrDepNotFound error when the dependencies are not found in the rulesfile.
var ErrDepNotFound = errors.New("dependencies not found")

// rulesfileDependencies given a rulesfile in yaml format it scans it nad extracts its dependencies.
func rulesfileDependencies(fileName string) ([]oci.ArtifactDependency, error) {
	var start bool
	var buf []byte
	var deps []oci.ArtifactDependency

	// Open the file.
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %q: %v", fileName, file)
	}

	// Prepare the file to be read line by line.
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)

	// Is appended to each line when inserted in the buffer.
	newLine := []byte("\n")

	// Falco rulesfiles are a list of dictionaries. We only want the "required plugin versions" by the ruleset. We do
	// not want to load all the file in memory, so we scan it line by line. When we reach the interested section we save
	// each line in a buffer, and after that we unmarshal it to a proper data structure.
	for fileScanner.Scan() {
		// If we have already found the section of interest, and we get a new item of the list then we stop.
		if start {
			if strings.HasPrefix(fileScanner.Text(), "-") {
				break
			} else {
				buf = append(buf, fileScanner.Bytes()...)
				buf = append(buf, newLine...)
			}
		} else {
			if strings.HasPrefix(fileScanner.Text(), depsKey) {
				start = true
			}
		}
	}

	if !start {
		return nil, fmt.Errorf("dependencies for rulesfile %q: %w", fileName, ErrDepNotFound)
	}

	if err := yaml.Unmarshal(buf, &deps); err != nil {
		return nil, fmt.Errorf("unable to unmarshal the required plugins versions: %w", err)
	}

	return deps, nil
}
