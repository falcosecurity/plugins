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
