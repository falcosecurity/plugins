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

package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/loader"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

const (
	defaultFieldsTag = "README-PLUGIN-FIELDS"
)

func fieldsRenderArgRow(a *sdk.FieldEntryArg) string {
	if !a.IsIndex && !a.IsKey {
		return "None"
	}

	var res []string
	if a.IsIndex {
		res = append(res, "Index")
	}
	if a.IsKey {
		res = append(res, "Key")
	}
	if a.IsRequired {
		res = append(res, "Required")
	}
	return strings.Join(res, ", ")
}

// renderNewLines replaces '\n' character with "<br/>" for proper table formatting.
func renderNewLines(desc string) string {
	return strings.ReplaceAll(desc, "\n", "<br/>")
}

func fieldsEditor(p *loader.Plugin, s string) (string, error) {
	if !p.HasCapExtraction() {
		return s, nil
	}

	fields := p.Fields()
	if len(fields) == 0 {
		return s, nil
	}

	var buf bytes.Buffer
	table := tablewriter.NewTable(&buf,
		tablewriter.WithRenderer(renderer.NewBlueprint()), // Use Blueprint
		tablewriter.WithRendition(tw.Rendition{
			Symbols: tw.NewSymbols(tw.StyleMarkdown),
			Borders: tw.Border{Left: tw.On, Right: tw.On, Top: tw.Off, Bottom: tw.Off}, // Markdown needs left/right borders
		}),
		tablewriter.WithHeaderAlignment(tw.AlignCenter), // Center align headers
		tablewriter.WithRowAlignment(tw.AlignLeft),      // Common for Markdown
		tablewriter.WithHeaderAutoWrap(tw.WrapNone),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithHeader([]string{"Name", "Type", "Arg", "Description"}),
	)
	for _, f := range fields {
		var row []string
		row = append(row, "`"+f.Name+"`")
		if f.IsList {
			row = append(row, "`"+f.Type+" (list)`")
		} else {
			row = append(row, "`"+f.Type+"`")
		}
		row = append(row, fieldsRenderArgRow(&f.Arg))
		row = append(row, renderNewLines(f.Desc))
		if err := table.Append(row); err != nil {
			return "", fmt.Errorf("failed to append field %v to table: %w", f.Name, err)
		}
	}

	if err := table.Render(); err != nil {
		return "", fmt.Errorf("failed to render table: %w", err)
	}

	return replateTag(s, fieldsTag, buf.String())
}
