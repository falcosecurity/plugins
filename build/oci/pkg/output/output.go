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

package output

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// Entry describes an entry of the output file.
type Entry struct {
	// Mandatory fields
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Registry   string `yaml:"registry"`
	Repository string `yaml:"repository"`
}

// Entries represents the content of the output file.
type Entries struct {
	Entries     []*Entry
	entryByName map[string]*Entry
}

// New returns a new empty entries.
func New() *Entries {
	return &Entries{
		entryByName: map[string]*Entry{},
	}
}

// EntryByName returns a Entry by passing its name.
func (e *Entries) EntryByName(name string) *Entry {
	return e.entryByName[name]
}

// Upsert adds a new entry to the Index or updates an existing one.
func (e *Entries) Upsert(entry *Entry) {
	for k, en := range e.Entries {
		if en.Name == entry.Name {
			e.Entries[k] = en
			return
		}
	}

	e.Entries = append(e.Entries, entry)

	entryName := entry.Name
	// When handling a rulesfile artifact we add the "-rules" suffix to its name
	// in order to distinguish it from the plugin artifact.
	if entry.Type == string(oci.Rulesfile) {
		entryName = entryName + "-rules"
	}
	e.entryByName[entry.Name] = entry
}

// Write writes entries to a file.
func (e *Entries) Write(path string) error {
	indexBytes, err := yaml.Marshal(e.Entries)
	if err != nil {
		return fmt.Errorf("an error occurred while marshalling: %w", err)
	}

	if err = os.WriteFile(path, indexBytes, fs.ModePerm); err != nil {
		return fmt.Errorf("an error occurred while writing entries to file %q: %w", path, err)
	}

	return nil
}

// Read reads entries from a file.
func (e *Entries) Read(path string) error {
	bytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("an error occurred while reading entries from file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(bytes, &e.Entries); err != nil {
		return fmt.Errorf("an error occurred while unmarshaling index: %w", err)
	}

	e.entryByName = make(map[string]*Entry, len(e.Entries))
	for _, entry := range e.Entries {
		e.Upsert(entry)
	}

	return nil
}
