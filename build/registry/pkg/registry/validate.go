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
	"fmt"
	"regexp"
)

var (
	rgxName   = regexp.MustCompile(`^[a-z]+[a-z0-9-_]*$`)
	rgxSource = regexp.MustCompile(`^[a-z]+[a-z0-9_]*$`)
)

func (s *SourcingCapability) validate(usedIDs map[uint]bool, forbiddenSources map[string]bool) error {
	if s.Supported {
		if s.ID > MaxPublicID {
			return fmt.Errorf("source ID outside the allowed range (%d): '%d'", MaxPublicID, s.ID)
		}
		if _, ok := usedIDs[s.ID]; ok {
			return fmt.Errorf("source ID is not unique: '%d'", s.ID)
		}
		// ID=0 is a special case and we don't want to define a source name
		if s.ID != 0 {
			if _, ok := forbiddenSources[s.Source]; ok {
				return fmt.Errorf("forbidden source name: '%s'", s.Source)
			}
			if !rgxSource.MatchString(s.Source) {
				return fmt.Errorf("source name does follow the naming convention: '%s'", s.Source)
			}
		}
		usedIDs[s.ID] = true
	}
	return nil
}

// Validates returns nil if the Registry is valid, and an error otherwise.
// For more details regarding which constraints are checked for validation,
// refer to: https://github.com/falcosecurity/plugins#registering-a-new-plugin
func (r *Registry) Validate() error {
	forbiddenSources := make(map[string]bool)
	for _, s := range r.ReservedSources {
		forbiddenSources[s] = true
	}

	ids := make(map[uint]bool)
	names := make(map[string]bool)
	for _, p := range r.Plugins {
		if !rgxName.MatchString(p.Name) {
			return fmt.Errorf("plugin name does follow the naming convention: '%s'", p.Name)
		}
		if _, ok := names[p.Name]; ok {
			return fmt.Errorf("plugin name is not unique: '%s'", p.Name)
		}
		if err := p.Capabilities.Sourcing.validate(ids, forbiddenSources); err != nil {
			return err
		}
		names[p.Name] = true
	}

	return nil
}
