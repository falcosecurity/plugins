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
	"fmt"
	"strings"
)

var (
	sourcePluginsTableContentType    = "plugins-source"
	extractorPluginsTableContentType = "plugins-extractor"
)

func (r *Registry) FormatMarkdownTable(contentType string) (string, error) {
	var ret strings.Builder
	wrapNotAvailable := func(s string) string {
		if len(s) == 0 {
			return "N/A"
		}
		return s
	}
	formatWithURL := func(s string, url string) string {
		if len(url) == 0 {
			return wrapNotAvailable(s)
		}
		return fmt.Sprintf("[%s](%s)", wrapNotAvailable(s), url)
	}

	switch contentType {
	case sourcePluginsTableContentType:
		ret.WriteString("| ID | Name | Event Source | Description | Info | Artifacts |\n")
		ret.WriteString("| --- | --- | --- | --- | --- | --- |\n")
		for _, s := range r.Plugins.Source {
			line := fmt.Sprintf("| %d | %s | `%s` | %s | Authors: %s <br/> License: %s | %s |\n",
				s.ID,
				formatWithURL(s.Name, s.SourcesURL),
				wrapNotAvailable(s.Source),
				wrapNotAvailable(s.Description),
				formatWithURL(s.Authors, s.Contact),
				wrapNotAvailable(s.License),
				formatWithURL(s.ArtifactsURL, s.ArtifactsURL),
			)
			ret.WriteString(line)
		}
	case extractorPluginsTableContentType:
		ret.WriteString("| Name | Extract Event Sources | Description | Info | Artifacts |\n")
		ret.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, e := range r.Plugins.Extractor {
			sources := make([]string, 0)
			for _, s := range e.Sources {
				sources = append(sources, fmt.Sprintf("`%s`", s))
			}
			line := fmt.Sprintf("| %s | %s | %s | Authors: %s <br/> License: %s | %s |\n",
				formatWithURL(e.Name, e.SourcesURL),
				wrapNotAvailable(strings.Join(sources, ", ")),
				wrapNotAvailable(e.Description),
				formatWithURL(e.Authors, e.Contact),
				wrapNotAvailable(e.License),
				formatWithURL(e.ArtifactsURL, e.ArtifactsURL),
			)
			ret.WriteString(line)
		}
	default:
		return "", fmt.Errorf("unknown table content type: %s", contentType)
	}

	return ret.String(), nil
}
