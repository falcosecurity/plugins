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
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const (
	defaultTableSubTag = "<!-- REGISTRY -->"
)

func loadRegistryFromFile(fname string) (*Registry, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return LoadRegistry(file)
}

func doCheck(fileName string) error {
	registry, err := loadRegistryFromFile(fileName)
	if err != nil {
		return err
	}
	return registry.Check()
}

func doTable(registryFile, subFile, subTag string) error {
	registry, err := loadRegistryFromFile(registryFile)
	if err != nil {
		return err
	}

	err = registry.Check()
	if err != nil {
		return err
	}

	table := registry.FormatMarkdownTable()
	if len(subFile) == 0 {
		fmt.Println(table)
	} else {
		if len(subTag) == 0 {
			return fmt.Errorf("subtag flag is required")
		}
		content, err := ioutil.ReadFile(subFile)
		if err != nil {
			return err
		}
		pieces := strings.SplitN(string(content), subTag, 3)
		if len(pieces) != 3 {
			return fmt.Errorf("can't find two instances of subtag in text file: '%s'", subTag)
		}
		contentStr := fmt.Sprintf("%s%s\n%s\n%s%s", pieces[0], subTag, table, subTag, pieces[2])
		if err = ioutil.WriteFile(subFile, []byte(contentStr), 0666); err != nil {
			return err
		}
	}

	return nil
}

func main() {
	checkCmd := &cobra.Command{
		Use:                   "check <filename>",
		Short:                 "Verify the correctness of a plugin registry YAML file",
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(c *cobra.Command, args []string) error {
			return doCheck(args[0])
		},
	}

	var tableSubFileName string
	var tableSubTab string
	tableCmd := &cobra.Command{
		Use:   "table <filename>",
		Short: "Format a plugin registry YAML file in a MarkDown table",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return doTable(args[0], tableSubFileName, tableSubTab)
		},
	}
	tableFlags := tableCmd.Flags()
	tableFlags.StringVar(&tableSubTab, "subtag", defaultTableSubTag, "A tag that delimits the start and the end of the text section to substitute with the generated table.")
	tableFlags.StringVar(&tableSubFileName, "subfile", "", "If specified, the table will be written inside the file at this path, inserting it between the first two instances of the substitution tag.")

	rootCmd := &cobra.Command{
		Use:     "registry",
		Version: "0.1.0",
	}
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(tableCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("error: %s\n", err)
		os.Exit(1)
	}
}
