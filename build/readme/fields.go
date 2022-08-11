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
	"bytes"

	"github.com/falcosecurity/plugin-sdk-go/pkg/loader"
	"github.com/olekukonko/tablewriter"
)

const (
	defaultFieldsTag = "README-PLUGIN-FIELDS"
)

func fieldsEditor(p *loader.Plugin, s string) (string, error) {
	if !p.HasCapExtraction() {
		return s, nil
	}

	fields := p.Fields()
	if len(fields) == 0 {
		return s, nil
	}

	var buf bytes.Buffer
	table := tablewriter.NewWriter(&buf)
	table.SetHeader([]string{"Name", "Type", "List", "Description"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.SetRowSeparator("-")
	table.SetAutoWrapText(false)
	for _, f := range fields {
		row := []string{}
		row = append(row, "`"+f.Name+"`")
		row = append(row, "`"+f.Type+"`")
		if f.IsList {
			row = append(row, "Yes")
		} else {
			row = append(row, "No")
		}
		row = append(row, f.Desc)
		table.Append(row)
	}
	table.Render()
	return replateTag(s, fieldsTag, buf.String())
}
