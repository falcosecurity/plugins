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

package cloudwatchlogs

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/falcosecurity/plugins/shared/go/aws/session"
)

const (
	DefaultShift           time.Duration = 1 * time.Second // controls the time shift in past for the first call to CloudwatchLogs API
	DefaultPollingInterval time.Duration = 5 * time.Second // time between two calls to CloudwatchLogs API
	DefaultBufferSize      uint64        = 200             // buffer size of the channel that transmits Logs to the Plugin
)

// Filter represents a filter for retrieving logs from CloudwatchLogs API
type Filter struct {
	FilterPattern       string
	LogGroupName        string
	LogStreamNamePrefix string
	LogStreamNames      string
}

// Client represents a client for CloudwatchLogs API
type Client struct {
	*cloudwatchlogs.CloudWatchLogs
}

// Options represents options for calls to CloudwatchLogs API
type Options struct {
	Shift           time.Duration
	PollingInterval time.Duration
	BufferSize      uint64
}

// CreateFilter returns a Client for retrieving logs from CloudwatchLogs API
func CreateFilter(filterPattern, logGroupName, logStreamNamePrefix, logStreamNames string) *Filter {
	return &Filter{
		FilterPattern:       filterPattern,
		LogGroupName:        logGroupName,
		LogStreamNamePrefix: logStreamNamePrefix,
		LogStreamNames:      logStreamNames,
	}
}

// CreateFilter returns a Filter for CloudwatchLogs API
func CreateClient(cfgs *aws.Config) *Client {
	return &Client{
		CloudWatchLogs: cloudwatchlogs.New(session.CreateSession(), cfgs),
	}
}

// setDefault set the default values for Options
func (options *Options) setDefault() {
	if options.PollingInterval == 0 {
		options.PollingInterval = DefaultPollingInterval
	}
	if options.Shift == 0 {
		options.Shift = DefaultShift
	}
	if options.BufferSize == 0 {
		options.BufferSize = DefaultBufferSize
	}
}

// Open returns an instance with the functionn called to retrieve logs
func (client *Client) Open(context context.Context, filter *Filter, options *Options) (chan *cloudwatchlogs.FilteredLogEvent, chan error) {
	options.setDefault()

	filters := &cloudwatchlogs.FilterLogEventsInput{
		StartTime:           time.Now().Add(-1 * options.Shift).UnixMilli(),
		FilterPattern:       aws.String(filter.FilterPattern),
		LogGroupName:        aws.String(filter.LogGroupName),
		LogStreamNamePrefix: aws.String(filter.LogStreamNamePrefix),
		LogStreamNames:      aws.String(filter.LogStreamNames),
	}

	eventC := make(chan []*cloudwatchlogs.FilteredLogEvent, options.BufferSize)
	errC := make(chan error)

	go func() {
		defer close(eventC)
		defer close(errC)

		for {
			logs, err := client.CloudWatchLogs.FilterLogEventsWithContext(aws.Context(context), filters)
			if err != nil {
				errC <- err
				return
			}
			if len(logs.Events) == 0 {
				time.Sleep(options.PollingInterval)
				continue
			}
			for _, i := range logs.Events {
				eventC <- i
			}
			if logs.NextToken != nil {
				filters.SetNextToken(*logs.NextToken)
				continue
			}
			filters.SetNextToken("")
			filters.StartTime(*logs[len(logs)-1].Timestamp + 1)
		}
	}()
	return eventC, errC
}
