package gcpaudit

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"google.golang.org/api/option"
)

func (p *Plugin) pullMsgsSync(ctx context.Context, projectID, subID string) (chan []byte, chan error) {
	var clientOptions []option.ClientOption
	if len(p.Config.CredentialsFile) > 0 {
		clientOptions = append(clientOptions, option.WithCredentialsFile(p.Config.CredentialsFile))
	}

	client, err := pubsub.NewClient(ctx, projectID, clientOptions...)
	if err != nil {
		fmt.Printf("pubsub.NewClient: %v", err)
	}

	sub := client.Subscription(subID)

	sub.ReceiveSettings.MaxOutstandingMessages = p.Config.MaxOutstandingMessages
	sub.ReceiveSettings.NumGoroutines = p.Config.NumGoroutines

	eventC := make(chan []byte)
	errC := make(chan error)

	go func() {

		defer close(eventC)
		defer close(errC)

		maxRetries := 3
		retryDelay := time.Second

		for retries := 0; retries < maxRetries; retries++ {

			err = performPubSubOperation(sub, ctx, eventC)

			if err == nil {
				// Operation succeeded, break out of the loop
				break
			}

			if isQuotaExceededError(err) {
				// Quota exceeded, wait for backoff duration and retry
				fmt.Printf("Quota exceeded. Retrying in %s\n", retryDelay)
				time.Sleep(retryDelay)
				retryDelay *= 2 // exponential backoff
			}

			if err != nil {
				errC <- err
				fmt.Printf("error is : %v", err)
				break
			}

		}

	}()

	return eventC, errC

}

func isQuotaExceededError(err error) bool {
	return strings.Contains(err.Error(), "quota exceeded")
}

func performPubSubOperation(subscription *pubsub.Subscription, ctx context.Context, eventC chan []byte) error {
	err := subscription.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		eventC <- msg.Data
		msg.Ack()
	})

	if err != nil {
		return err
	}
	return nil
}

func (p *Plugin) String(evt sdk.EventReader) (string, error) {

	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}
