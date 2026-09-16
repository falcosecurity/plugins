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

package k8sauditaks

import (
	"context"
	"fmt"

	"github.com/segmentio/kafka-go/sasl"
)

// oauthBearerMechanism implements SASL/OAUTHBEARER (RFC 7628) initial
// response and challenge handling. segmentio/kafka-go ships PLAIN and
// SCRAM mechanisms but not OAUTHBEARER, which the Event Hubs Kafka
// endpoint requires to authenticate with an Azure AD access token.
type oauthBearerMechanism struct {
	// TokenProvider returns a valid OAuth bearer token on every call. It is
	// invoked once per connection, so it is safe (and expected) to return a
	// cached token when the underlying credential's token is still valid.
	TokenProvider func(ctx context.Context) (string, error)
}

func (m oauthBearerMechanism) Name() string { return "OAUTHBEARER" }

// Start builds the SASL/OAUTHBEARER initial client response:
//
//	gs2-header kvsep "auth=Bearer " token kvsep kvsep
//
// with no channel binding and no authzid, gs2-header is "n,,", and kvsep is
// the 0x01 control character.
func (m oauthBearerMechanism) Start(ctx context.Context) (sasl.StateMachine, []byte, error) {
	token, err := m.TokenProvider(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("oauthbearer: failed to acquire token: %w", err)
	}
	resp := []byte(fmt.Sprintf("n,,\x01auth=Bearer %s\x01\x01", token))
	return m, resp, nil
}

// Next handles the (only possible) server response to the initial
// response: either the exchange is already done (empty challenge), or the
// server rejected the token and sent a JSON error challenge, to which the
// client must reply with a single control-A to end the exchange.
func (m oauthBearerMechanism) Next(_ context.Context, challenge []byte) (bool, []byte, error) {
	if len(challenge) > 0 {
		return false, []byte("\x01"), fmt.Errorf("oauthbearer: authentication rejected: %s", challenge)
	}
	return true, nil, nil
}
