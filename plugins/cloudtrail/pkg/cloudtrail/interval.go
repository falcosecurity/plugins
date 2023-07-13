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

package cloudtrail

import (
	"regexp"
	"strconv"
	"time"
)

var RFC3339Simple = "2006-01-02T03:04:05Z"

func parseEndpoint(endpoint string) (time.Time, error) {
	utc := time.Now().UTC()
	var endpointTime time.Time
	var err error

	durationRE := regexp.MustCompile(`^(\d+)([wdhms])$`)
	matches := durationRE.FindStringSubmatch(endpoint)
	if matches != nil {
		durI, err := strconv.Atoi(matches[1])
		if err == nil {
			duration := time.Duration(durI)
			switch matches[2] {
			case "w":
				duration *= time.Hour * 24 * 7
			case "d":
				duration *= time.Hour * 24
			case "h":
				duration *= time.Hour
			case "m":
				duration *= time.Minute
			case "s":
				duration *= time.Second
			}
			endpointTime = utc.Add(- duration)
		}
	} else {
		endpointTime, err = time.Parse(RFC3339Simple, endpoint)
	}
	return endpointTime, err
}

// endTime will be zero if no end interval was supplied.
func ParseInterval(interval string) (time.Time, time.Time, error) {
	var startTime time.Time
	var endTime time.Time
	var err error

	// First, see if we have an interval.
	intervalRE := regexp.MustCompile(`(.*)\s*-\s*(\d+[wdhms]|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$`)
	matches := intervalRE.FindStringSubmatch(interval)
	if matches != nil {
		startTime, err = parseEndpoint(matches[1])
		if err == nil {
			endTime, err = parseEndpoint(matches[2])
		}
	} else if interval != "" {
		startTime, err = parseEndpoint(interval)
	}
	return startTime, endTime, err
}
