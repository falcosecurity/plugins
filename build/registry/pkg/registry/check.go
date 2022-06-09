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

package registry

import (
	"fmt"
	"os"
	"regexp"
)

var (
	rgxName *regexp.Regexp
)

func init() {
	var err error
	rgxName, err = regexp.Compile(`^[a-z]+[a-z0-9_]*$`)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}
}

func (s *SourcingCapability) Check(usedIDs map[uint]bool, forbiddenSources map[string]bool) error {
	if s.Supported {
		if s.ID == 0 {
			return fmt.Errorf("forbidden source ID: '%d'", s.ID)
		}
		if _, ok := usedIDs[s.ID]; ok {
			return fmt.Errorf("source id is not unique: '%d'", s.ID)
		}
		if _, ok := forbiddenSources[s.Source]; ok {
			return fmt.Errorf("forbidden source name: '%s'", s.Source)
		}
		if !rgxName.MatchString(s.Source) {
			return fmt.Errorf("source name does follow the naming convention: '%s'", s.Source)
		}
		usedIDs[s.ID] = true
	}
	return nil
}

func (r *Registry) Check() error {
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
		if err := p.Capabilities.Sourcing.Check(ids, forbiddenSources); err != nil {
			return err
		}
		names[p.Name] = true
	}

	return nil
}
