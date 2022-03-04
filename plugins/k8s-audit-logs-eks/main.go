/*
Copyright (C) 2021 The Falco Authors.

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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	k8sextractor "github.com/falcosecurity/plugins/plugins/k8s-audit-logs/pkg/extractor"
	k8sfields "github.com/falcosecurity/plugins/plugins/k8s-audit-logs/pkg/fields"
	"github.com/falcosecurity/plugins/share/go/pkg/aws/cloudwatchlogs"
)

type K8SAuditLogsEKSPlugin struct {
	plugins.BasePlugin
}

type K8SAuditLogsEKSInstance struct {
	source.BaseInstance
	Client *cloudwatchlogs.Client
	Filter *cloudwatchlogs.Filter
}

func init() {
	p := &K8SAuditLogsEKSPlugin{}
	extractor.Register(p)
	source.Register(p)
}

func (m *K8SAuditLogsEKSPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 7,
		Name:               "k8s-audit-logs-eks",
		Description:        "K8S Audit Logs of EKS from Cloudwatch Logs",
		Contact:            "github.com/falcosecurity/plugins/",
		Version:            "0.1.0",
		RequiredAPIVersion: "0.3.0",
		EventSource:        "k8s_audit_eks",
	}
}

func (m *K8SAuditLogsEKSPlugin) Init(config string) error {
	return nil
}

func (m *K8SAuditLogsEKSPlugin) Fields() []sdk.FieldEntry {
	return k8sfields.GetFields()
}

func (p *K8SAuditLogsEKSPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	return k8sextractor.Extract(req, evt)
}

func (m *K8SAuditLogsEKSPlugin) Open(params string) (source.Instance, error) {
	var obj map[string]string
	err := json.Unmarshal([]byte(params), &obj)
	if err != nil {
		return nil, fmt.Errorf("params %s could not be parsed: %v", params, err)
	}
	if _, ok := obj["cluster"]; !ok {
		return nil, fmt.Errorf("params %s did not contain cluster property", params)
	}
	if _, ok := obj["region"]; !ok {
		return nil, fmt.Errorf("params %s did not contain region property", params)
	}

	filter := cloudwatchlogs.GetFilter()
	filter.FilterLogEventsInput.SetLogGroupName("/aws/eks/" + obj["cluster"] + "/cluster")
	filter.FilterLogEventsInput.SetLogStreamNamePrefix("kube-apiserver-audit")
	filter.FilterLogEventsInput.SetStartTime(time.Now().Add(-10 * time.Second).UnixMilli())

	return &K8SAuditLogsEKSInstance{
		Client: cloudwatchlogs.GetClient(aws.NewConfig().WithRegion(obj["region"])),
		Filter: filter,
	}, nil
}

func (m *K8SAuditLogsEKSPlugin) String(in io.ReadSeeker) (string, error) {
	var value string
	encoder := gob.NewDecoder(in)
	if err := encoder.Decode(&value); err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", value), nil
}

func (m *K8SAuditLogsEKSInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	m.Filter.Limit = aws.Int64(int64(evts.Len()))
	nb, err, lastTimetamp := m.Client.NextBatch(m.Filter, pState, evts)
	if lastTimetamp != 0 {
		m.Filter.FilterLogEventsInput.StartTime = aws.Int64(lastTimetamp)
	}
	return nb, err
}

func main() {}
