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

package cloudwatchlogs

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
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
	LogStreamNames      []string
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

// CreateOptions returns Options for retrieving logs from CloudwatchLogs API
func CreateOptions(shift, pollingInterval time.Duration, bufferSize uint64) *Options {
	options := new(Options)
	options.Shift = shift
	options.PollingInterval = pollingInterval
	options.BufferSize = bufferSize
	options.setDefault()
	return options
}

// setDefault set the default values for Options
func (options *Options) setDefault() {
	if options.Shift == 0 {
		options.Shift = DefaultShift
	}
	if options.PollingInterval == 0 {
		options.PollingInterval = DefaultPollingInterval
	}
	if options.BufferSize == 0 {
		options.BufferSize = DefaultBufferSize
	}
}

// CreateFilter returns a Client for retrieving logs from CloudwatchLogs API
func CreateFilter(filterPattern, logGroupName, logStreamNamePrefix string, logStreamNames []string) *Filter {
	if logStreamNamePrefix == "" {
		logStreamNamePrefix = "*"
	}

	return &Filter{
		FilterPattern:       filterPattern,
		LogGroupName:        logGroupName,
		LogStreamNamePrefix: logStreamNamePrefix,
		LogStreamNames:      logStreamNames,
	}
}

// CreateFilter returns a Filter for CloudwatchLogs API
func CreateClient(sess *session.Session, cfgs *aws.Config) *Client {
	return &Client{
		CloudWatchLogs: cloudwatchlogs.New(sess, cfgs),
	}
}

// Open returns an instance with the functionn called to retrieve logs
func (client *Client) Open(context context.Context, filter *Filter, options *Options) (chan *cloudwatchlogs.FilteredLogEvent, chan error) {
	if options == nil {
		options = new(Options)
		options.setDefault()
	}

	filters := &cloudwatchlogs.FilterLogEventsInput{
		StartTime:           aws.Int64(time.Now().Add(-1 * options.Shift).UnixMilli()),
		FilterPattern:       aws.String(filter.FilterPattern),
		LogGroupName:        aws.String(filter.LogGroupName),
		LogStreamNamePrefix: aws.String(filter.LogStreamNamePrefix),
	}

	if len(filter.LogStreamNamePrefix) == 0 {
		filters.LogStreamNames = aws.StringSlice(filter.LogStreamNames)
	}

	eventC := make(chan *cloudwatchlogs.FilteredLogEvent, options.BufferSize)
	errC := make(chan error)

	go func() {
		defer close(eventC)
		defer close(errC)
		for {
			var lastEventTime int64
			err := client.CloudWatchLogs.FilterLogEventsPagesWithContext(aws.Context(context), filters,
				func(page *cloudwatchlogs.FilterLogEventsOutput, lastPage bool) bool {
					if len(page.Events) == 0 {
						return false
					}
					for _, i := range page.Events {
						eventC <- i
						if lastEventTime < *i.Timestamp {
							lastEventTime = *i.Timestamp
						}
					}
					return true
				})
			if err != nil {
				errC <- err
				return
			}

			time.Sleep(options.PollingInterval)
			if lastEventTime > 0 {
				filters.SetStartTime(lastEventTime + 1)
			}
		}
	}()
	return eventC, errC
}
