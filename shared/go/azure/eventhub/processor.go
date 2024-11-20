package eventhub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"golang.org/x/time/rate"
)

type Processor struct {
	RateLimiter *rate.Limiter
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
) error {
	defer closePartitionResources(partitionClient)

	for {
		ctx := context.Background()

		receiveCtx, receiveCtxCancel := context.WithTimeout(ctx, time.Minute)
		fmt.Printf("Receiving events on partitionId %v\n", partitionClient.PartitionID())
		events, err := partitionClient.ReceiveEvents(receiveCtx, 100, nil)
		fmt.Printf("Received %d events on partitionId %v\n", len(events), partitionClient.PartitionID())
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
				ctx := context.Background()
				err := p.RateLimiter.Wait(ctx)
				if err != nil {
					continue
				}
				recordChan <- record
			}

			if err := partitionClient.UpdateCheckpoint(ctx, event, nil); err != nil {
				return err
			}
			fmt.Printf("Updated checkpoint for partitionId %v\n", partitionClient.PartitionID())
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
	defer partitionClient.Close(context.TODO())
}
