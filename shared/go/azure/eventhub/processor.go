// SPDX-License-Identifier: Apache-2.0
/*
   Copyright (C) 2024 The Falco Authors.
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

package eventhub

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"golang.org/x/time/rate"
)

type Processor struct {
	RateLimiter *rate.Limiter
	Logger      *log.Logger
}

type Record struct {
	Properties struct {
		Log string `json:"log"`
	} `json:"properties"`
}

type Event struct {
	Records []Record `json:"records"`
}

func (p *Processor) Process(
	partitionClient *azeventhubs.ProcessorPartitionClient,
	recordChan chan<- Record,
	ctx context.Context,
) error {
	defer closePartitionResources(partitionClient)

	for {
		receiveCtx, receiveCtxCancel := context.WithTimeout(ctx, time.Second*10)
		events, err := partitionClient.ReceiveEvents(receiveCtx, 100, nil)
		receiveCtxCancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}

		for _, event := range events {
			eventData, err := UnmarshallEvent(event.Body)
			if err != nil {
				return err
			}
			for _, record := range eventData.Records {
				err := p.RateLimiter.Wait(ctx)
				if err != nil {
					continue
				}
				select {
				case <-ctx.Done():
					return nil
				case recordChan <- record:
				}
			}

			if err := partitionClient.UpdateCheckpoint(ctx, event, nil); err != nil {
				return err
			}
		}
	}
}

func UnmarshallEvent(eventJObj []byte) (*Event, error) {
	var event Event
	err := json.Unmarshal(eventJObj, &event)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func closePartitionResources(partitionClient *azeventhubs.ProcessorPartitionClient) {
	defer partitionClient.Close(context.Background())
}
