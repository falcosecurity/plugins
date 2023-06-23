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
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/plugins/build/registry/internal/options"
	"github.com/falcosecurity/plugins/build/registry/pkg/check"
	"github.com/falcosecurity/plugins/build/registry/pkg/distribution"
	"github.com/falcosecurity/plugins/build/registry/pkg/oci"
	"github.com/falcosecurity/plugins/build/registry/pkg/table"
)

const (
	defaultTableSubTag = "<!-- REGISTRY -->"
)

var (
	out = bufio.NewWriter(os.Stdout)
)

func main() {
	defer out.Flush()

	opts := options.NewCommonOptions(
		options.WithContext(context.Background()),
		options.WithOutput(out),
	)

	checkCmd := &cobra.Command{
		Use:                   "check <filename>",
		Short:                 "Verify the correctness of a plugin registry YAML file",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return check.DoCheck(args[0])
		},
	}

	var tableSubFileName string
	var tableSubTab string
	tableCmd := &cobra.Command{
		Use:   "table <filename>",
		Short: "Format a plugin registry YAML file in a MarkDown table",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return table.DoTable(args[0], tableSubFileName, tableSubTab)
		},
	}
	tableFlags := tableCmd.Flags()
	tableFlags.StringVar(&tableSubTab, "subtag", defaultTableSubTag, "A tag that delimits the start and the end of the text section to substitute with the generated table.")
	tableFlags.StringVar(&tableSubFileName, "subfile", "", "If specified, the table will be written inside the file at this path, inserting it between the first two instances of the substitution tag.")

	updateIndexCmd := &cobra.Command{
		Use:                   "update-index <registryFilename> <indexFilename>",
		Short:                 "Update an index file for artifacts distribution using registry data",
		Args:                  cobra.ExactArgs(2),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return distribution.DoUpdateIndex(args[0], args[1])
		},
	}

	updateOCIRegistry := &cobra.Command{
		Use:                   "update-oci-registry <registryFilename>",
		Short:                 "Update the oci registry starting from the registry file and s3 bucket",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			status, err := oci.DoUpdateOCIRegistry(opts.Context, args[0])
			if err != nil {
				return err
			}

			return oci.PrintUpdateStatus(status, opts.Output)
		},
	}

	rootCmd := &cobra.Command{
		Use:     "registry",
		Version: "0.2.0",
	}
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(tableCmd)
	rootCmd.AddCommand(updateIndexCmd)
	rootCmd.AddCommand(updateOCIRegistry)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
