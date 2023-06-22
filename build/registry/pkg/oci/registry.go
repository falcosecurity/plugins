package oci

import (
	"encoding/json"
	"io"

	"github.com/pkg/errors"

	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
)

func PrintUpdateStatus(newArtifacts registry.ArtifactsPushStatus, output io.Writer) error {
	bytes, err := json.Marshal(newArtifacts)
	if err != nil {
		return errors.Wrap(err, "error marshaling oci registry push metadata")
	}
	output.Write(bytes)

	return nil
}
