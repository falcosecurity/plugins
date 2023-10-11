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

	"gopkg.in/yaml.v2"
)

type encoder interface {
	Encode(io.Writer) error
}

// Encode writes the content to a io.Writer
func (r *SourcingCapability) Encode(w io.Writer) error {
	return yaml.NewEncoder(w).Encode(r)
}

// Encode writes the content to a io.Writer
func (r *ExtractionCapability) Encode(w io.Writer) error {
	return yaml.NewEncoder(w).Encode(r)
}

// Encode writes the content to a io.Writer
func (r *Capabilities) Encode(w io.Writer) error {
	return yaml.NewEncoder(w).Encode(r)
}

// Encode writes the content to a io.Writer
func (r *Plugin) Encode(w io.Writer) error {
	return yaml.NewEncoder(w).Encode(r)
}

// Encode writes the content to a io.Writer
func (r *Registry) Encode(w io.Writer) error {
	return yaml.NewEncoder(w).Encode(r)
}

// Decode fills the structure by reading from a io.Reader
func (r *SourcingCapability) Decode(w io.Reader) error {
	return yaml.NewDecoder(w).Decode(r)
}

// Decode fills the structure by reading from a io.Reader
func (r *ExtractionCapability) Decode(w io.Reader) error {
	return yaml.NewDecoder(w).Decode(r)
}

// Decode fills the structure by reading from a io.Reader
func (r *Capabilities) Decode(w io.Reader) error {
	return yaml.NewDecoder(w).Decode(r)
}

// Decode fills the structure by reading from a io.Reader
func (r *Plugin) Decode(w io.Reader) error {
	return yaml.NewDecoder(w).Decode(r)
}

// Decode fills the structure by reading from a io.Reader
func (r *Registry) Decode(w io.Reader) error {
	return yaml.NewDecoder(w).Decode(r)
}
