/*
Copyright (C) 2022 The Falco Authors.

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
		out    *bytes.Buffer
		status registry.ArtifactsPushStatus
		opts   *options.CommonOptions
		err    error
	)

	Context("Print update result", func() {
		BeforeEach(func() {
			out = new(bytes.Buffer)
			opts = options.NewCommonOptions(options.WithOutput(out))
		})

		When("at least one artifact has been pushed to the OCI registry", func() {
			BeforeEach(func() {
				status = registry.ArtifactsPushStatus{
					{
						Repository: registry.RepositoryMetadata{
							Ref: samplePluginRepoRef,
						},
						Artifact: registry.ArtifactMetadata{
							Digest: sampleDigest,
							Tags:   []string{samplePluginTag}},
					},
				}
				err = oci.PrintUpdateStatus(status, opts.Output)
			})

			It("should not fail", func() {
				Expect(err).To(BeNil())
			})
			It("output should not be empty", func() {
				Expect(out.String()).ToNot(BeEmpty())
			})
			It("output should contain a valid JSON", func() {
				status = registry.ArtifactsPushStatus{}
				err := json.Unmarshal(out.Bytes(), &status)
				Expect(err).To(BeNil())
			})
		})

		When("no artifacts have been pushed to the OCI registry", func() {
			BeforeEach(func() {
				status = registry.ArtifactsPushStatus{}
				err = oci.PrintUpdateStatus(status, opts.Output)
			})

			It("should not fail", func() {
				Expect(err).To(BeNil())
			})
			It("output should not be empty", func() {
				Expect(out.String()).ToNot(BeEmpty())
			})
			It("output should contain a valid JSON", func() {
				status = registry.ArtifactsPushStatus{}
				err := json.Unmarshal(out.Bytes(), &status)
				Expect(err).To(BeNil())
			})
		})
	})
})
