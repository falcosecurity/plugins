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
	"errors"
	"testing"
)

func TestOAuthBearerMechanismName(t *testing.T) {
	m := oauthBearerMechanism{}
	if m.Name() != "OAUTHBEARER" {
		t.Fatalf("got %q, want OAUTHBEARER", m.Name())
	}
}

func TestOAuthBearerMechanismStart(t *testing.T) {
	m := oauthBearerMechanism{
		TokenProvider: func(ctx context.Context) (string, error) {
			return "my-token", nil
		},
	}

	sess, ir, err := m.Start(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess == nil {
		t.Fatalf("expected a non-nil state machine")
	}

	want := "n,,\x01auth=Bearer my-token\x01\x01"
	if string(ir) != want {
		t.Fatalf("got %q, want %q", ir, want)
	}
}

func TestOAuthBearerMechanismStartTokenError(t *testing.T) {
	m := oauthBearerMechanism{
		TokenProvider: func(ctx context.Context) (string, error) {
			return "", errors.New("boom")
		},
	}

	if _, _, err := m.Start(context.Background()); err == nil {
		t.Fatalf("expected an error")
	}
}

func TestOAuthBearerMechanismNext(t *testing.T) {
	m := oauthBearerMechanism{}

	done, resp, err := m.Next(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !done {
		t.Fatalf("expected done=true on an empty challenge")
	}
	if resp != nil {
		t.Fatalf("expected a nil response, got %q", resp)
	}

	done, resp, err = m.Next(context.Background(), []byte(`{"status":"invalid_token"}`))
	if err == nil {
		t.Fatalf("expected an error on a rejection challenge")
	}
	if done {
		t.Fatalf("expected done=false on a rejection challenge")
	}
	if resp != nil {
		// kafka-go's SASL loop discards the response whenever Next returns
		// an error (see dialer.go's authenticateSASL), so there's nothing
		// to send back - confirm we don't pretend otherwise.
		t.Fatalf("expected a nil response on a rejection challenge, got %q", resp)
	}
}
