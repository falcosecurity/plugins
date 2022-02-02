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

package main

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

func (s *Source) Check(reserved []string) error {

	if s.ID == 0 {
		return fmt.Errorf("forbidden source ID: '%d'", s.ID)
	}

	if !rgxName.MatchString(s.Name) {
		return fmt.Errorf("name does follow the naming convention: '%s'", s.Name)
	}

	for _, source := range reserved {
		if s.Source == source {
			return fmt.Errorf("forbidden source name: '%s'", s.Source)
		}
	}

	if !rgxName.MatchString(s.Source) {
		return fmt.Errorf("source name does follow the naming convention: '%s'", s.Source)
	}

	return nil
}

func (e *Extractor) Check() error {
	if !rgxName.MatchString(e.Name) {
		return fmt.Errorf("name does follow the naming convention: '%s'", e.Name)
	}

	return nil
}

func (p *Plugins) Check(reserved []string) error {
	ids := make(map[uint]bool)
	names := make(map[string]bool)

	for _, s := range p.Source {
		if err := s.Check(reserved); err != nil {
			return err
		}
		if _, ok := names[s.Name]; ok {
			return fmt.Errorf("plugin name is not unique: '%s'", s.Name)
		}
		if _, ok := ids[s.ID]; ok {
			return fmt.Errorf("source id is not unique: '%d'", s.ID)
		}
		names[s.Name] = true
		ids[s.ID] = true
	}

	for _, e := range p.Extractor {
		if err := e.Check(); err != nil {
			return err
		}
		if _, ok := names[e.Name]; ok {
			return fmt.Errorf("plugin name is not unique: '%s'", e.Name)
		}
		names[e.Name] = true
	}

	return nil
}

func (r *Registry) Check() error {
	return r.Plugins.Check(r.ReservedSources)
}
