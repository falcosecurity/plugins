package registry

import (
	"bytes"
)

func encodeString(r encoder) string {
	buf := bytes.Buffer{}
	err := r.Encode(&buf)
	if err != nil {
		return "string encoding error: " + err.Error()
	}
	return buf.String()
}

// String implements the fmt.Stringer interface
func (r *SourcingCapability) String() string {
	return encodeString(r)
}

// String implements the fmt.Stringer interface
func (r *ExtractionCapability) String() string {
	return encodeString(r)
}

// String implements the fmt.Stringer interface
func (r *Capabilities) String() string {
	return encodeString(r)
}

// String implements the fmt.Stringer interface
func (r *Plugin) String() string {
	return encodeString(r)
}

// String implements the fmt.Stringer interface
func (r *Registry) String() string {
	return encodeString(r)
}
