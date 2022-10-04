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

package github

import (
	"regexp"
)

///////////////////////////////////////////////////////////////////////////////
// These are the regular expressions that are used to determine if commits
// contain secrets.
// You can add your own to the list.
//
// Some entries are courtesy of git-secrets:
// https://github.com/awslabs/git-secrets/blob/master/git-secrets#L233
// Some entries are courtesy of gitleaks:
// https://github.com/zricethezav/gitleaks/blob/f338bc584fbebcecb5dc372b40e2be86634f2143/config/gitleaks.toml
// https://github.com/zricethezav/gitleaks/blob/f62617d7a6ddcb81ca72ee293a3d0c72bb738a67/examples/leaky-repo.toml
///////////////////////////////////////////////////////////////////////////////
var minersChecks = []string{
	"xmrig",
	"ccminer",
	"t-rex",
	"stratum",
	"pool",
	"hashrate",
	"cryptonight",
	"wallet",
	"gminer",
	"gpuminer",
	"cpuminer",
	"nanominer",
	"nicehash",
	"xmr-stak",
	"nbminer",
	"srbminer",
	"hiveos",
	"ethermine",
	"kryptex",
	"2miners",
	"betterhash",
	"minerstat",
	"raveos",
	"f2pool",
	"unmineable",
	"minergate",
	"cryptotab",
	"lolminer",
	"phoenixminer",
}

var minerRegexList = []*regexp.Regexp{}

func findMiner(text string) string {
	for j, re := range minerRegexList {
		if re.MatchString(text) {
			return minersChecks[j]
		}
	}

	return ""
}

func compileMinerRegexes(oCtx *PluginInstance) error {
	for _, mi := range minersChecks {
		re, err := regexp.Compile(mi)
		if err != nil {
			return err
		}
		minerRegexList = append(minerRegexList, re)
	}

	return nil
}
