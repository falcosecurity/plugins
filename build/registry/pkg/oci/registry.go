package oci

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/falcosecurity/plugins/build/registry/internal/options"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
)

func UpdateOCIRegistry(registryFile string, opts *options.CommonOptions) error {
	res, err := DoUpdateOCIRegistry(context.Background(), registryFile)
	if err != nil {
		return err
	}

	return PrintUpdateResult(res, opts)
}

func PrintUpdateResult(res registry.ArtifactPushMetadataList, opts *options.CommonOptions) error {
	bytes, err := json.Marshal(res)
	if err != nil {
		return errors.Wrap(err, "error marshaling oci registry push metadata")
	}
	opts.Output.Write(bytes)

	return nil
}
