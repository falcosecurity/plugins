package oci_test

import (
	"bytes"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/falcosecurity/plugins/build/registry/internal/options"
	"github.com/falcosecurity/plugins/build/registry/pkg/oci"
	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
)

var _ = Describe("Update OCI registry", func() {
	var (
		out  *bytes.Buffer
		res  registry.ArtifactPushMetadataList
		opts *options.CommonOptions
		err  error
	)

	Context("Print update result", func() {
		BeforeEach(func() {
			out = new(bytes.Buffer)
			opts = options.NewCommonOptions(options.WithOutput(out))
		})

		When("at least one artifact has been pushed to the OCI registry", func() {
			BeforeEach(func() {
				res = registry.ArtifactPushMetadataList{
					{
						Repository: registry.RepositoryMetadata{
							Ref: samplePluginRepoRef,
						},
						Artifact: registry.ArtifactMetadata{
							Digest: sampleDigest,
							Tags:   []string{samplePluginTag}},
					},
				}
				err = oci.PrintUpdateResult(res, opts)
			})

			It("should not fail", func() {
				Expect(err).To(BeNil())
			})
			It("output should not be empty", func() {
				Expect(out.String()).ToNot(BeEmpty())
			})
			It("output should contain a valid JSON", func() {
				res = registry.ArtifactPushMetadataList{}
				err := json.Unmarshal(out.Bytes(), &res)
				Expect(err).To(BeNil())
			})
		})

		When("no artifacts have been pushed to the OCI registry", func() {
			BeforeEach(func() {
				res = registry.ArtifactPushMetadataList{}
				err = oci.PrintUpdateResult(res, opts)
			})

			It("should not fail", func() {
				Expect(err).To(BeNil())
			})
			It("output should not be empty", func() {
				Expect(out.String()).ToNot(BeEmpty())
			})
			It("output should contain a valid JSON", func() {
				res = registry.ArtifactPushMetadataList{}
				err := json.Unmarshal(out.Bytes(), &res)
				Expect(err).To(BeNil())
			})
		})
	})
})
