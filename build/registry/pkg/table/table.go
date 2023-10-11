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

package table

import (
	"fmt"
	"os"
	"strings"

	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
)

func DoTable(registryFile, subFile, subTag string) error {
	r, err := registry.LoadRegistryFromFile(registryFile)
	if err != nil {
		return err
	}

	err = r.Validate()
	if err != nil {
		return err
	}

	table, err := formatMarkdownTable(r)
	if err != nil {
		return err
	}
	if len(subFile) == 0 {
		fmt.Println(table)
	} else {
		if len(subTag) == 0 {
			return fmt.Errorf("subtag flag is required")
		}
		content, err := os.ReadFile(subFile)
		if err != nil {
			return err
		}
		pieces := strings.SplitN(string(content), subTag, 3)
		if len(pieces) != 3 {
			return fmt.Errorf("can't find two instances of subtag in text file: '%s'", subTag)
		}
		contentStr := fmt.Sprintf("%s%s\n%s\n%s%s", pieces[0], subTag, table, subTag, pieces[2])
		if err = os.WriteFile(subFile, []byte(contentStr), 0666); err != nil {
			return err
		}
	}

	return nil
}

func formatMarkdownTable(r *registry.Registry) (string, error) {
	var ret strings.Builder
	ret.WriteString("| Name | Capabilities | Description\n")
	ret.WriteString("| --- | --- | --- |\n")
	for _, p := range r.Plugins {
		line := fmt.Sprintf("| %s | %s | %s  <br/><br/> Authors: %s <br/> License: %s |\n",
			formatMarkdownStringWithURL(r, p.Name, p.URL),
			formatMarkdownCapabilities(r, &p.Capabilities),
			formatMarkdownStringNotAvailable(r, p.Description),
			formatMarkdownStringWithURL(r, p.Authors, p.Contact),
			formatMarkdownStringNotAvailable(r, p.License),
		)
		ret.WriteString(line)
	}
	return ret.String(), nil
}

func formatMarkdownCapabilities(r *registry.Registry, caps *registry.Capabilities) string {
	var ret strings.Builder
	if caps.Sourcing.Supported {
		ret.WriteString(fmt.Sprintf("**Event Sourcing** <br/>ID: %d <br/>`%s`",
			caps.Sourcing.ID,
			caps.Sourcing.Source,
		))
	}
	if caps.Extraction.Supported {
		if ret.Len() > 0 {
			ret.WriteString(" <br/>")
		}
		ret.WriteString("**Field Extraction** <br/> ")
		if len(caps.Extraction.Sources) == 0 {
			if caps.Sourcing.Supported {
				ret.WriteString("`" + caps.Sourcing.Source + "`")
			} else {
				ret.WriteString("*All Sources*")
			}
		} else {
			var sources []string
			for _, s := range caps.Extraction.Sources {
				sources = append(sources, "`"+s+"`")
			}
			ret.WriteString(strings.Join(sources, ", "))
		}
	}
	return ret.String()
}

func formatMarkdownStringNotAvailable(r *registry.Registry, s string) string {
	if len(s) == 0 {
		return "N/A"
	}
	return s
}

func formatMarkdownStringWithURL(r *registry.Registry, s, url string) string {
	if len(url) == 0 {
		return formatMarkdownStringNotAvailable(r, s)
	}
	return fmt.Sprintf("[%s](%s)", formatMarkdownStringNotAvailable(r, s), url)
}
