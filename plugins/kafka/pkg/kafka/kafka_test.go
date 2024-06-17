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
package kafka

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/testcontainers/testcontainers-go"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugins/plugins/kafka/pkg/helpers"
	"github.com/segmentio/kafka-go"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
)

func TestPlugin(t *testing.T) {
	ctx := context.Background()
	kafkaContainer, err := tckafka.RunContainer(
		ctx,
		testcontainers.WithImage("confluentinc/confluent-local:7.5.0"))

	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if err := kafkaContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}()

	brokers, err := kafkaContainer.Brokers(ctx)

	if err != nil {
		t.Fatal(err)
	}

	controllerConn, err := kafka.Dial("tcp", brokers[0])

	if err != nil {
		t.Fatal(err)
	}

	defer func(controllerConn *kafka.Conn) {
		err := controllerConn.Close()
		if err != nil {
			t.Fatal(err)
		}
	}(controllerConn)

	err = controllerConn.CreateTopics(kafka.TopicConfig{
		Topic:             "example-topic",
		NumPartitions:     1,
		ReplicationFactor: 1,
	})

	if err != nil {
		t.Fatal(err)
	}

	writer := &kafka.Writer{
		Addr:     kafka.TCP(brokers[0]),
		Topic:    "example-topic",
		Balancer: &kafka.LeastBytes{},
	}

	defer func(writer *kafka.Writer) {
		err := writer.Close()
		if err != nil {
			t.Fatal(err)
		}
	}(writer)

	if err := writer.WriteMessages(ctx, kafka.Message{Value: []byte(`{"hello": "world"}`)}); err != nil {
		t.Fatal(err)
	}

	configBuffer := &bytes.Buffer{}
	initConfig := PluginConfig{
		GroupId: "example-group",
		Brokers: brokers,
		Topics:  []string{"example-topic"},
	}

	if err := json.NewEncoder(configBuffer).Encode(initConfig); err != nil {
		t.Fatal(err)
	}

	initConfigString := configBuffer.String()

	t.Run("Init", func(t *testing.T) {
		plugin := &Plugin{}
		err := plugin.Init(initConfigString)

		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Open", func(t *testing.T) {
		plugin := &Plugin{}

		err := plugin.Init(initConfigString)

		if err != nil {
			t.Fatal(err)
		}

		mockWriter := &helpers.MockWriter{Buffer: &bytes.Buffer{}}
		eventWriters := &helpers.MockWriters{Writers: []sdk.EventWriter{mockWriter}}
		instance, err := plugin.Open(``)

		if err != nil {
			t.Fatal(err)
		}

		for {
			_, err = instance.NextBatch(nil, eventWriters)

			if !errors.Is(err, sdk.ErrTimeout) {
				break
			}
		}

		if err != nil {
			t.Fatal(err)
		}

		if mockWriter.Buffer.String() != `{"hello": "world"}` {
			t.Fail()
		}
	})

	t.Run("Destroy", func(t *testing.T) {
		plugin := &Plugin{}
		err := plugin.Init(initConfigString)

		if err != nil {
			t.Fatal(err)
		}

		_, err = plugin.Open(``)

		if err != nil {
			t.Fatal(err)
		}

		plugin.Destroy()
	})
}
