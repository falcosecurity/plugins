package oci_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	samplePluginRepoRef = "ghcr.io/falcosecurity/plugins/plugins/k8saudit"
	sampleDigest = "sha256:454b5d97ecbb71c8b605af2028f12fc2c792e363b150b1aeeb773c802699d647"
	samplePluginTag     = "1.0.0"
)

func TestOCI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OCI Suite")
}
