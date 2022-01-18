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

func (r *Registry) FormatMarkdownTable() string {
	var ret strings.Builder
	wrapNotAvailable := func(s string) string {
		if len(s) == 0 {
			return "N/A"
		}
		return s
	}

	ret.WriteString("## Source Plugins\n")
	ret.WriteString("| ID | Event Source | Name | Description | Info |\n")
	ret.WriteString("| --- | --- | --- | --- | ---|\n")
	for _, s := range r.Plugins.Source {
		line := fmt.Sprintf("| %d | %s | `%s` | %s | Authors: %s <br/> Repository: %s <br/> Contact: %s |\n",
			s.ID,
			wrapNotAvailable(s.Name),
			wrapNotAvailable(s.Source),
			wrapNotAvailable(s.Description),
			wrapNotAvailable(s.Authors),
			wrapNotAvailable(s.Repository),
			wrapNotAvailable(s.Contact),
		)
		ret.WriteString(line)
	}
	ret.WriteString("\n## Extractor Plugins\n")
	ret.WriteString("| Name | Extract Event Sources | Description | Info |\n")
	ret.WriteString("| --- | --- | --- | --- |\n")
	for _, e := range r.Plugins.Extractor {
		sources := make([]string, 0)
		for _, s := range e.Sources {
			sources = append(sources, fmt.Sprintf("`%s`", s))
		}
		line := fmt.Sprintf("| %s | %s | %s | Authors: %s <br/> Repository: %s <br/> Contact: %s |\n",
			e.Name,
			wrapNotAvailable(strings.Join(sources, ", ")),
			wrapNotAvailable(e.Description),
			wrapNotAvailable(e.Authors),
			wrapNotAvailable(e.Repository),
			wrapNotAvailable(e.Contact),
		)
		ret.WriteString(line)
	}
	return ret.String()
}
