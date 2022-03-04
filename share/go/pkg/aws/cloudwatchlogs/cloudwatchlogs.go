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
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugins/share/go/pkg/aws/session"
)

// Client represents a client for CloudwatchLogs API
type Client struct {
	*cloudwatchlogs.CloudWatchLogs
}

// Filter represents a filter for the query to CloudwatchLogs API
type Filter struct {
	*cloudwatchlogs.FilterLogEventsInput
}

// GetClient returns a Client for CloudwatchLogs API
func GetClient(cfgs *aws.Config) *Client {
	return &Client{
		CloudWatchLogs: cloudwatchlogs.New(session.GetSession(), cfgs),
	}
}

// GetFilter returns a filter for the query to CloudwatchLogs API
func GetFilter() *Filter {
	return &Filter{&cloudwatchlogs.FilterLogEventsInput{}}
}

// NextBatch returns events from CloudwatchLogs
func (client *Client) NextBatch(filter *Filter, pState sdk.PluginState, evts sdk.EventWriters) (int, error, int64) {
	cfi := &cloudwatchlogs.FilterLogEventsInput{
		EndTime:             filter.FilterLogEventsInput.EndTime,
		FilterPattern:       filter.FilterLogEventsInput.FilterPattern,
		Interleaved:         filter.FilterLogEventsInput.Interleaved,
		Limit:               filter.FilterLogEventsInput.Limit,
		LogGroupName:        filter.FilterLogEventsInput.LogGroupName,
		LogStreamNamePrefix: filter.FilterLogEventsInput.LogStreamNamePrefix,
		LogStreamNames:      filter.FilterLogEventsInput.LogStreamNames,
		NextToken:           filter.FilterLogEventsInput.NextToken,
		StartTime:           time.Now().UnixMilli(),
	}

	logs, err := client.CloudWatchLogs.FilterLogEvents(cfi)
	if err != nil {
		fmt.Println(err)
		return 0, sdk.ErrEOF, 0
	}
	var lastTimestamp int64
	for n := 0; n < evts.Len() && n < len(logs.Events); n++ {
		evt := evts.Get(n)
		log := logs.Events[n]

		// fmt.Println(*log.Message)

		lastTimestamp = *log.Timestamp
		evt.SetTimestamp(uint64(lastTimestamp))

		_, err := evt.Writer().Write([]byte(*log.Message))
		if err != nil {
			return n, err, lastTimestamp
		}
	}
	return len(logs.Events), nil, lastTimestamp
}
