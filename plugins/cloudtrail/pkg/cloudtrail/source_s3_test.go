// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

package cloudtrail

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// newFakeS3Server serves ListObjectsV2 requests for a bucket that contains
// CloudTrail logs of account 111111111111 for two regions, with one log file
// before, one inside and one after 2026-01-01T00:00:00Z-2026-01-02T00:00:00Z.
func newFakeS3Server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := r.URL.Query().Get("prefix")
		var body strings.Builder
		body.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bucket</Name><IsTruncated>false</IsTruncated>`)
		switch {
		case r.URL.Query().Get("delimiter") == "" && strings.Contains(prefix, "111111111111/CloudTrail/"):
			// Keys of a single region.
			for _, ts := range []string{"2025/12/31/111111111111_CloudTrail_r_20251231T2355Z", "2026/01/01/111111111111_CloudTrail_r_20260101T1200Z", "2026/01/03/111111111111_CloudTrail_r_20260103T0000Z"} {
				fmt.Fprintf(&body, "<Contents><Key>%s%s_x.json.gz</Key></Contents>", prefix, ts)
			}
		case r.URL.Query().Get("delimiter") == "":
			// A plain listing of the prefix, without any filtering.
			for _, region := range []string{"us-east-1", "eu-west-1"} {
				for _, ts := range []string{"2025/12/31/111111111111_CloudTrail_r_20251231T2355Z", "2026/01/01/111111111111_CloudTrail_r_20260101T1200Z", "2026/01/03/111111111111_CloudTrail_r_20260103T0000Z"} {
					fmt.Fprintf(&body, "<Contents><Key>%s111111111111/CloudTrail/%s/%s_x.json.gz</Key></Contents>", prefix, region, ts)
				}
			}
		case strings.HasSuffix(prefix, "/CloudTrail/"):
			// Regions of an account.
			for _, region := range []string{"us-east-1", "eu-west-1"} {
				fmt.Fprintf(&body, "<CommonPrefixes><Prefix>%s%s/</Prefix></CommonPrefixes>", prefix, region)
			}
		default:
			// Accounts of an organization.
			fmt.Fprintf(&body, "<CommonPrefixes><Prefix>%s111111111111/</Prefix></CommonPrefixes>", prefix)
		}
		body.WriteString("</ListBucketResult>")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(body.String()))
	}))
}

func TestOpenS3Interval(t *testing.T) {
	tests := []struct {
		name        string
		params      string
		accountList string
		expected    []string
	}{
		{
			name:   "account trail at the bucket root",
			params: "s3://bucket/AWSLogs/111111111111/",
			expected: []string{
				"AWSLogs/111111111111/CloudTrail/eu-west-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
				"AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
			},
		},
		{
			name:   "account trail below a prefix",
			params: "s3://bucket/logs/AWSLogs/111111111111",
			expected: []string{
				"logs/AWSLogs/111111111111/CloudTrail/eu-west-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
				"logs/AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
			},
		},
		{
			name:   "organization trail at the bucket root",
			params: "s3://bucket/AWSLogs/o-abcdefghij/",
			expected: []string{
				"AWSLogs/o-abcdefghij/111111111111/CloudTrail/eu-west-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
				"AWSLogs/o-abcdefghij/111111111111/CloudTrail/us-east-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
			},
		},
		{
			name:        "organization trail at the bucket root with an account list",
			params:      "s3://bucket/AWSLogs/o-abcdefghij",
			accountList: "111111111111",
			expected: []string{
				"AWSLogs/o-abcdefghij/111111111111/CloudTrail/eu-west-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
				"AWSLogs/o-abcdefghij/111111111111/CloudTrail/us-east-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
			},
		},
		{
			name:   "pre-ControlTower organization trail at the bucket root",
			params: "s3://bucket/AWSLogs/",
			expected: []string{
				"AWSLogs/111111111111/CloudTrail/eu-west-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
				"AWSLogs/111111111111/CloudTrail/us-east-1/2026/01/01/111111111111_CloudTrail_r_20260101T1200Z_x.json.gz",
			},
		},
	}

	server := newFakeS3Server()
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oCtx := &PluginInstance{}
			oCtx.config.Reset()
			oCtx.config.S3DownloadConcurrency = 1
			oCtx.config.S3Interval = "2026-01-01T00:00:00Z-2026-01-02T00:00:00Z"
			oCtx.config.S3AccountList = tt.accountList
			oCtx.s3.client = s3.New(s3.Options{
				BaseEndpoint: aws.String(server.URL),
				Region:       "us-east-1",
				UsePathStyle: true,
				Credentials:  aws.AnonymousCredentials{},
			})

			if err := oCtx.openS3(tt.params); err != nil {
				t.Fatalf("openS3 failed: %v", err)
			}

			var files []string
			for _, f := range oCtx.files {
				files = append(files, f.name)
			}
			sort.Strings(files)
			if strings.Join(files, "\n") != strings.Join(tt.expected, "\n") {
				t.Fatalf("got files:\n%s\nwant:\n%s", strings.Join(files, "\n"), strings.Join(tt.expected, "\n"))
			}
		})
	}
}
