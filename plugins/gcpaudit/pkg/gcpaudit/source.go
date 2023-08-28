package gcpaudit

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"google.golang.org/api/option"
)

func (p *Plugin) pullMsgsSync(ctx context.Context, subscriptionID string) (chan []byte, chan error) {
	var clientOptions []option.ClientOption
	if len(p.Config.CredentialsFile) > 0 {
		clientOptions = append(clientOptions, option.WithCredentialsFile(p.Config.CredentialsFile))
	}

	errC := make(chan error)
	eventC := make(chan []byte)
	go func() {
		defer close(eventC)
		defer close(errC)

		// create pubsub client
		client, err := pubsub.NewClient(ctx, p.Config.ProjectID, clientOptions...)
		if err != nil {
			errC <- err
			return
		}

		// attempt subscribing with exponential backoff
		sub := client.Subscription(subscriptionID)
		sub.ReceiveSettings.MaxOutstandingMessages = p.Config.MaxOutstandingMessages
		sub.ReceiveSettings.NumGoroutines = p.Config.NumGoroutines
		maxRetries := 3
		retryDelay := time.Second
		for retries := 0; retries < maxRetries; retries++ {
			err = performPubSubOperation(sub, ctx, eventC)
			if err == nil {
				// Operation succeeded, break out of the loop
				return
			} else if isQuotaExceededError(err) {
				// Quota exceeded, wait for backoff duration and retry
				fmt.Printf("[gcpaudit] pubsub receive quota exceeded, retrying in %s\n", retryDelay.String())
				time.Sleep(retryDelay)
				retryDelay *= 2 // exponential backoff
			} else {
				errC <- err
				return
			}
		}

	}()

	return eventC, errC
}

func isQuotaExceededError(err error) bool {
	return strings.Contains(err.Error(), "quota exceeded")
}

func performPubSubOperation(subscription *pubsub.Subscription, ctx context.Context, eventC chan []byte) error {
	return subscription.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		eventC <- msg.Data
		msg.Ack()
	})
}

func (p *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := io.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)
	return fmt.Sprintf("%v", evtStr), nil
}
