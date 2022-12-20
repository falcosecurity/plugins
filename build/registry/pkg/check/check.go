package check

import "github.com/falcosecurity/plugins/build/registry/pkg/registry"

// DoCheck loads the registry.yaml file from disk and validates it.
func DoCheck(fileName string) error {
	registry, err := registry.LoadRegistryFromFile(fileName)
	if err != nil {
		return err
	}
	return registry.Validate()
}
