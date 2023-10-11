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
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/loader"
	"github.com/spf13/pflag"
)

var (
	pluginPath string
	readmePath string
	fieldsTag  string
)

type EditorFunc func(*loader.Plugin, string) (string, error)

func fail(err error) {
	println(err.Error())
	os.Exit(1)
}

func replateTag(s string, t string, r string) (string, error) {
	startTag := "<!-- " + t + " -->\n"
	endTag := "<!-- /" + t + " -->\n"
	start := 0
	for {
		start = strings.Index(s[start:], startTag)
		if start < 0 {
			return s, nil
		}
		start += len(startTag)
		end := strings.Index(s[start:], endTag)
		if end < 0 {
			return "", fmt.Errorf("can't find end tag: " + endTag)
		}
		end += start
		s = s[:start] + r + s[end:]
		start += len(r) + len(endTag)
	}
}

func editFile(plugin *loader.Plugin, path string, editors ...EditorFunc) error {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	edited := string(bytes)
	for _, editor := range editors {
		edited, err = editor(plugin, edited)
		if err != nil {
			return err
		}
	}
	return ioutil.WriteFile(path, ([]byte)(edited), 0)
}

func main() {
	pflag.StringVarP(&pluginPath, "plugin", "p", "", "File path to the plugin shared library.")
	pflag.StringVarP(&readmePath, "file", "f", "", "File path to the README file to be edited.")
	pflag.StringVar(&fieldsTag, "fields-tag", defaultFieldsTag, "Tag to substitute with the plugin fields table.\nIn the file, formatted as \"<!-- TAG -->\\n...\\n<!-- /TAG -->\".")
	pflag.Parse()
	if len(pluginPath) == 0 {
		fail(fmt.Errorf("must specify a plugin path with the -p option"))
	}
	if len(readmePath) == 0 {
		fail(fmt.Errorf("must specify a file path with the -f option"))
	}

	// load plugin
	plugin, err := loader.NewPlugin(pluginPath)
	if err != nil {
		fail(err)
	}
	defer plugin.Unload()

	// use plugin info to edit readme file
	err = editFile(plugin, readmePath, fieldsEditor)
	if err != nil {
		fail(err)
	}
}
