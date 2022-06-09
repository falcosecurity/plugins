package registry

import (
	"io"
)

// Load reads from a io.Reader and uses the content to populate and
// return a new instance of Registry
func Load(r io.Reader) (*Registry, error) {
	registry := &Registry{}
	return registry, registry.Decode(r)
}
