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

const (
	aws      = "(AWS|aws|Aws)?_?"
	quote    = "(\"|')"
	connect  = "\\s*(:|=>|=)\\s*"
	optQuote = quote + "?"
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
var secretsChecks = []secretCheckInfo{
	{"aws_access_key", "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "key", "AWS"},
	{"aws_secret_key", optQuote + aws + "(SECRET|secret|Secret)?_?(ACCESS|access|Access)?_?(KEY|key|Key)" + optQuote + connect + optQuote + "[A-Za-z0-9/\\+=]{40}" + optQuote, "key", "AWS"},
	{"aws_mws_key", "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "key", "AWS"},
	{"aws_account_id", optQuote + aws + "(ACCOUNT|account|Account)_?(ID|id|Id)?" + optQuote + connect + optQuote + "[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}" + optQuote, "key", "AWS"},
	{"facebook_secret_key", "(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]", "key", "Facebook"},
	{"facebook_client_id", "(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]", "key", "Facebook"},
	{"twitter_secret_key", "(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]", "key", "Twitter"},
	{"twitter_client_id", "(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]", "client", "Twitter"},
	{"github_personal_access_token", "ghp_[0-9a-zA-Z]{36}", "key", "Github"},
	{"github_oauth_access_token", "gho_[0-9a-zA-Z]{36}", "key", "Github"},
	{"github_app_token", "(ghu|ghs)_[0-9a-zA-Z]{36}", "key", "Github"},
	{"github_refresh_token", "ghr_[0-9a-zA-Z]{76}", "key", "Github"},
	{"linkedin_client_id", "(?i)linkedin(.{0,20})?(?-i)[0-9a-z]{12}", "client", "LinkedIn"},
	{"linkedin_secret_key", "(?i)linkedin(.{0,20})?[0-9a-z]{16}", "secret", "LinkedIn"},
	{"slack", "xox[baprs]-([0-9a-zA-Z]{10,48})?", "key", "Slack"},
	{"asymmetric_private_key", "-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----", "key", "AsymmetricPrivateKey"},
	{"google_api_key", "AIza[0-9A-Za-z\\-_]{35}", "key", "Google"},
	{"google_gcp_service_account", "\"type\": \"service_account\"", "key", "Google"},
	{"heroku_api_key", "(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "key", "Heroku"},
	{"mailchimp_api_key", "(?i)(mailchimp|mc)(.{0,20})?[0-9a-f]{32}-us[0-9]{1,2}", "key", "Mailchimp"},
	{"mailgun_api_key", "((?i)(mailgun|mg)(.{0,20})?)?key-[0-9a-z]{32}", "key", "Mailgun"},
	{"paypal_braintree_access_token", "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}", "key", "Paypal"},
	{"picatic_api_key", "sk_live_[0-9a-z]{32}", "key", "Picatic"},
	{"sendgrid_api_key", "SG\\.[\\w_]{16,32}\\.[\\w_]{16,64}", "key", "SendGrid"},
	{"slack_webhook", "^https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}$", "key", "slack"},
	{"stripe_api_key", "(?i)stripe(.{0,20})?[sr]k_live_[0-9a-zA-Z]{24}", "key", "Stripe"},
	{"square_access_token", "sq0atp-[0-9A-Za-z\\-_]{22}", "key", "square"},
	{"square_oauth_secret", "sq0csp-[0-9A-Za-z\\-_]{43}", "key", "square"},
	{"twilio_api_key", "(?i)twilio(.{0,20})?SK[0-9a-f]{32}", "key", "twilio"},
	{"dynatrace_token", "dt0[a-zA-Z]{1}[0-9]{2}\\.[A-Z0-9]{24}\\.[A-Z0-9]{64}", "key", "Dynatrace"},
	{"shopify_shared_secret", "shpss_[a-fA-F0-9]{32}", "key", "Shopify"},
	{"shopify_access_token", "shpat_[a-fA-F0-9]{32}", "key", "Shopify"},
	{"shopify_custom_app_access_token", "shpca_[a-fA-F0-9]{32}", "key", "Shopify"},
	{"shopify_private_app_access_token", "shppa_[a-fA-F0-9]{32}", "key", "Shopify"},
	{"pypi_upload_token", "pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}", "key", "pypi"},
}

type secretCheckInfo struct {
	desc       string
	regex      string
	secretType string
	platform   string
}

var regexList = []*regexp.Regexp{}

func findSecret(text string) *secretCheckInfo {
	for j, re := range regexList {
		if re.MatchString(text) {
			return &secretsChecks[j]
		}
	}

	return nil
}

func compileRegexes(oCtx *PluginInstance) error {
	for _, mi := range secretsChecks {
		re, err := regexp.Compile(mi.regex)
		if err != nil {
			return err
		}
		regexList = append(regexList, re)
	}

	return nil
}
