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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/falcosecurity/plugins/build/registry/pkg/registry"
	"github.com/spf13/pflag"
)

const (
	commitHashMaxLen = 7
	commitLinkFmt    = "https://github.com/falcosecurity/plugins/commit/%s"
	commitMsgMaxLen  = 80
)

func git(args ...string) (output []string, err error) {
	fmt.Fprintln(os.Stderr, "git ", strings.Join(args, " "))
	stdout, err := exec.Command("git", args...).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, errors.New("git (" + exitErr.String() + "): " + string(exitErr.Stderr))
		}
		return nil, err
	}
	return strings.Split(string(stdout), "\n"), nil
}

// an empty string matches the last tag with no match filtering
func gitGetLatestTagWithMatch(match []string) (string, error) {
	args := []string{"describe", "--tags", "--abbrev=0"}
	if len(match) > 0 {
		for _, m := range match {
			args = append(args, "--match", m)
		}
	}
	tags, err := git(args...)
	if err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", errors.New("git tag not found")
	}
	return tags[0], nil
}

// an empty tag lists commit from whole history
func gitListCommits(from, to string) ([]string, error) {
	revRange := ""
	if len(to) > 0 {
		revRange = to
	}
	if len(from) > 0 {
		if len(revRange) == 0 {
			revRange = "HEAD"
		}
		revRange = from + ".." + revRange
	}
	logs, err := git("log", revRange, "--oneline")
	if err != nil {
		return nil, err
	}
	return logs, nil
}

func pluginSource(pname string) string {
	reg, err := registry.LoadRegistryFromFile("registry.yaml")
	if err != nil {
		fail(fmt.Errorf("an error occurred while loading registry entries from file %q: %v", "registry.yaml", err))
	}

	for _, plugin := range reg.Plugins {
		if plugin.Name == pname && plugin.Capabilities.Sourcing.Supported {
			return plugin.Capabilities.Sourcing.Source
		}
	}

	return ""
}

func fail(err error) {
	fmt.Printf("error: %s\n", err)
	os.Exit(1)
}

// formats the line with markdown syntax and decorates it
func formatCommitLine(c string) string {
	firstSpace := strings.Index(c, " ")
	hash := strings.Trim(c[:firstSpace], " ")    // hash is before the first space
	message := strings.Trim(c[firstSpace:], " ") // message is after the first space
	if len(message) > commitMsgMaxLen {
		message = message[:commitMsgMaxLen-3] + "..."
	}
	commitLink := fmt.Sprintf(commitLinkFmt, hash)
	return fmt.Sprintf("* [`%s`](%s) %s", hash[:commitHashMaxLen], commitLink, message)
}

func main() {
	var plugin string
	var from string
	var to string
	pflag.StringVar(&plugin, "plugin", "", "Name of the plugin to generate the changelog for")
	pflag.StringVar(&from, "from", "", "Tag/branch/hash from which start listing commits")
	pflag.StringVar(&to, "to", "HEAD", "Tag/branch/hash to which stop listing commits")
	pflag.Parse()

	// if from is not specified, we use the latest tag matching the plugin name
	if len(from) == 0 {
		match := []string{}
		if len(plugin) > 0 {
			match = append(match, "plugins/"+plugin+"/v[0-9]*.[0-9]*.[0-9]*")
			match = append(match, plugin+"-[0-9]*.[0-9]*.[0-9]*")
		}
		tag, err := gitGetLatestTagWithMatch(match)
		if err != nil {
			fmt.Fprintln(os.Stderr, "no matching tag found for plugin '"+plugin+"', using commits from whole history:", err.Error())
		} else {
			from = tag
		}
	}

	// get all commits
	commits, err := gitListCommits(from, to)
	if err != nil {
		fail(err)
	}

	var rgx, rgxSource, rgxDeps *regexp.Regexp
	if len(plugin) > 0 {
		// craft a regex to filter all plugin-related commits that follow
		// the conventional commit format
		rgx, _ = regexp.Compile("^[a-f0-9]+ [a-zA-Z]+\\(([a-zA-Z\\/]+\\/)?" + plugin + "(\\/[a-zA-Z\\/]+)?\\):.*")

		// use source name of the plugin as well, if it has sourcing capabilities
		pluginSource := pluginSource(plugin)
		if pluginSource != "" {
			rgxSource, _ = regexp.Compile("^[a-f0-9]+ [a-zA-Z]+\\(([a-zA-Z\\/]+\\/)?" + pluginSource + "(\\/[a-zA-Z\\/]+)?\\):.*")
		}

		// craft a regex to filter all plugin-related dependabot commits
		rgxDeps, _ = regexp.Compile("^[a-f0-9]+ build\\(deps\\):.*" + plugin + "$")
	}

	for _, c := range commits {
		if len(c) > 0 && (rgx == nil || rgx.MatchString(c) ||
			(rgxSource != nil && rgxSource.MatchString(c)) ||
			rgxDeps.MatchString(c)) {
			fmt.Println(formatCommitLine(c) + "\n")
		}
	}
}
