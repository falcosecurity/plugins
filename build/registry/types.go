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
	"io"

	"github.com/go-yaml/yaml"
)

type Source struct {
	ID          uint   `yaml:"id"`
	Source      string `yaml:"source"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Authors     string `yaml:"authors"`
	Contact     string `yaml:"contact"`
	Repository  string `yaml:"repository"`
}

type Extractor struct {
	Sources     []string `yaml:"sources"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Authors     string   `yaml:"authors"`
	Contact     string   `yaml:"contact"`
	Repository  string   `yaml:"repository"`
}

type Plugins struct {
	Source    []Source    `yaml:"source"`
	Extractor []Extractor `yaml:"extractor"`
}

type Registry struct {
	Plugins Plugins `yaml:"plugins"`
}

func LoadRegistry(r io.Reader) (*Registry, error) {
	decoder := yaml.NewDecoder(r)
	registry := &Registry{}
	if err := decoder.Decode(registry); err != nil {
		return nil, err
	}
	return registry, nil
}
