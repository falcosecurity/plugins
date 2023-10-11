// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

package distribution_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/falcosecurity/plugins/build/registry/pkg/distribution"
)

const (
	indexFile         = "testdata/index.yaml"
	wrongIndexFile    = "testdata/wrong-index.yaml"
	registryFile      = "testdata/registry.yaml"
	wrongRegistryFile = "testdata/wrong-registry.yaml"
	registryUser      = "falcosecurity"
	registryName      = "ghcr.io"
)

var _ = Describe("Update index", func() {
	var (
		err error
	)
	Context("with registry file", func() {
		BeforeEach(func() {
			os.Setenv("REGISTRY_USER", registryUser)
			os.Setenv("REGISTRY", registryName)
		})
		Context("with index file", func() {
			BeforeEach(func() {
				err = distribution.DoUpdateIndex(registryFile, indexFile)
			})
			It("Should not fail", func() {
				Expect(err).To(BeNil())
			})
		})
		Context("without index file", func() {
			BeforeEach(func() {
				err = distribution.DoUpdateIndex(registryFile, wrongIndexFile)
			})
			It("Should fail", func() {
				Expect(err).ToNot(BeNil())
			})
		})
	})
	Context("without registry file", func() {
		BeforeEach(func() {
			os.Setenv("REGISTRY_USER", registryUser)
			os.Setenv("REGISTRY", registryName)
		})
		Context("with index file", func() {
			BeforeEach(func() {
				err = distribution.DoUpdateIndex(wrongRegistryFile, indexFile)
			})
			It("Should fail", func() {
				Expect(err).ToNot(BeNil())
			})
		})
		Context("without index file", func() {
			BeforeEach(func() {
				err = distribution.DoUpdateIndex(wrongRegistryFile, wrongIndexFile)
			})
			It("Should fail", func() {
				Expect(err).ToNot(BeNil())
			})
		})
	})
})
