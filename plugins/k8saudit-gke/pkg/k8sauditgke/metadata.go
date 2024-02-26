// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

package k8sauditgke

import (
	"fmt"

	"github.com/patrickmn/go-cache"
	mrpb "google.golang.org/genproto/googleapis/api/monitoredres"
)

func (p *Plugin) getClusterLabels(resource *mrpb.MonitoredResource) (map[string]string, error) {
	clusterName := getClusterName(resource)

	var extraLabels map[string]string
	labels, found := p.metadataCache.Get(clusterName)
	if found {
		extraLabels = labels.(map[string]string)
	} else {
		var err error
		extraLabels, err = p.fetchClusterLabels(clusterName)
		if err != nil {
			return nil, err
		}
	}

	return extraLabels, nil
}

func getClusterName(resource *mrpb.MonitoredResource) string {
	projectId := resource.Labels["project_id"]
	location := resource.Labels["location"]
	clusterName := resource.Labels["cluster_name"]
	return fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectId, location, clusterName)
}

func (p *Plugin) fetchClusterLabels(clusterName string) (map[string]string, error) {
	p.logger.Printf("Fetching metadata for '%s'", clusterName)
	cluster, err := p.containerService.Projects.Locations.Clusters.Get(clusterName).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %v", err)
	}
	labels := make(map[string]string, len(cluster.ResourceLabels))
	for lbl, lblValue := range cluster.ResourceLabels {
		labels[lbl] = lblValue
	}
	p.metadataCache.Add(clusterName, labels, cache.DefaultExpiration)
	return labels, nil
}
