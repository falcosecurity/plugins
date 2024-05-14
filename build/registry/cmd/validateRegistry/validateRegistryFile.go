package validateRegistry

import (
	"context"
	"fmt"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	"github.com/falcosecurity/plugins/build/registry/pkg/oci"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
	"strings"
)

func NewValidateRegistry(ctx context.Context) *cobra.Command {
	updateOCIRegistry := &cobra.Command{
		Use:                   "validate-registry <registryFilename>",
		Short:                 "Check that an OCI repo exists for each plugin in the registry file",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return validateRegistry(ctx, args[0])
		},
	}

	return updateOCIRegistry
}

func validateRegistry(ctx context.Context, registryFile string) error {
	reg, err := registry.LoadRegistryFromFile(registryFile)
	if err != nil {
		return fmt.Errorf("an error occurred while loading registry entries from file %q: %v", registryFile, err)
	}

	ociClient := authn.NewClient()

	puller := ocipuller.NewPuller(ociClient, false, nil)
	// For each plugin in the registry index, look for new ones to be released, and publish them.
	for _, plugin := range reg.Plugins {
		// Filter out plugins that are not owned by falcosecurity.
		if !strings.HasPrefix(plugin.URL, oci.PluginsRepo) {
			klog.V(2).Infof("skipping plugin %q with authors %q: it is not maintained by %q",
				plugin.Name, plugin.Authors, oci.FalcoAuthors)
			continue
		}
		klog.Infof("Checking OCI repo for plugin %q", plugin.Name)
		ref := fmt.Sprintf("ghcr.io/falcosecurity/plugins/plugin/%s:latest", plugin.Name)
		if _, err := puller.PullConfigLayer(ctx, ref); err != nil {
			return fmt.Errorf("plugin %s seems to not have an OCI repository: %w", plugin.Name, err)
		}
	}

	return nil
}
