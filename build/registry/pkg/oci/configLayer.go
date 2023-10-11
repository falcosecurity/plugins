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
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/plugins/build/registry/pkg/common"
)

// rulesFileConfig generates the artifact configuration for a rulesfile starting form the tar.gz archive,
// its name and version.
func rulesfileConfig(name, version, filePath string) (*oci.ArtifactConfig, error) {
	// Create temp dir.
	tmpDir, err := os.MkdirTemp("", "registry-oci-")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary dir while preparing to extract rulesfile %q: %v", filePath, err)
	}
	defer os.RemoveAll(tmpDir)
	files, err := common.ExtractTarGz(filePath, tmpDir)
	if err != nil {
		return nil, err
	}

	cfg := &oci.ArtifactConfig{
		Name:         name,
		Version:      version,
		Dependencies: nil,
		Requirements: nil,
	}

	for _, file := range files {
		// Get the requirements for the given file.
		req, err := rulesfileRequirement(file)
		if err != nil && !errors.Is(err, ErrReqNotFound) {
			return nil, err
		}
		// If found add it to the requirements list.
		if err == nil {
			_ = cfg.SetRequirement(req.Name, req.Version)
		}

		deps, err := rulesfileDependencies(file)
		if err != nil && !errors.Is(err, ErrDepNotFound) {
			return nil, err
		}
		// If found add it to the dependencies list.
		if err == nil {
			for _, d := range deps {
				_ = cfg.SetDependency(d.Name, d.Version, d.Alternatives)
			}
		}
	}

	if cfg.Dependencies == nil || cfg.Requirements == nil {
		return nil, fmt.Errorf("no dependencies or requirements found for rulesfile %q", filePath)
	}

	return cfg, nil
}

func pluginConfig(name, version, filePath string) (*oci.ArtifactConfig, error) {
	// Create temp dir.
	tmpDir, err := os.MkdirTemp("", "registry-oci-")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary dir while preparing to extract plugin %q: %v", filePath, err)
	}
	defer os.RemoveAll(tmpDir)
	files, err := common.ExtractTarGz(filePath, tmpDir)
	if err != nil {
		return nil, err
	}

	cfg := &oci.ArtifactConfig{
		Name:         name,
		Version:      version,
		Dependencies: nil,
		Requirements: nil,
	}

	for _, file := range files {
		// skip files that are not a shared library such as README files.
		if !strings.HasSuffix(file, ".so") {
			continue
		}
		// Get the requirement for the given file.
		req, err := pluginRequirement(file)
		if err != nil && !errors.Is(err, ErrReqNotFound) {
			return nil, err
		}
		// If found add it to the requirements list.
		if err == nil {
			_ = cfg.SetRequirement(req.Name, req.Version)
		}
	}

	if cfg.Requirements == nil {
		return nil, fmt.Errorf("no requirements found for plugin %q", filePath)
	}

	return cfg, nil
}
