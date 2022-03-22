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

package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
)

func (k *K8SAuditPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	err := k.extractor.ExtractFromEvent(req, evt)
	// We want to keep not-available errors internal. Propagating
	// this error is useful to implement a clean extraction logic, however
	// this kind of error would be very noisy for the framework and is not
	// truly relevant. Plus, the plugin framework understands that a field
	// is not present by checking that sdk.ExtractRequest.SetValue() has not
	// being invoked.
	if err == k8saudit.ErrExtractNotAvailable {
		return nil
	}
	return err
}

func (k *K8SAuditPlugin) Fields() []sdk.FieldEntry {
	return k8saudit.Fields()
}
