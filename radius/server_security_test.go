// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package radius

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	radiuslib "layeh.com/radius"
)

func TestDisabledRadiusPortNeverStartsListener(t *testing.T) {
	original := listenAndServeRadius
	t.Cleanup(func() { listenAndServeRadius = original })

	for _, port := range []string{"", "0", "-1", "not-a-port", "65536"} {
		t.Run(port, func(t *testing.T) {
			called := false
			listenAndServeRadius = func(_ *radiuslib.PacketServer) error {
				called = true
				return nil
			}
			t.Setenv("radiusServerPort", port)
			t.Setenv("radiusServerEnabled", "true")
			t.Setenv("radiusSecret", "a-non-default-radius-secret")
			StartRadiusServer()
			if called {
				t.Fatalf("RADIUS listener started for disabled/invalid port %q", port)
			}
		})
	}
}

func TestEnabledRadiusPortUsesExactListenerAddress(t *testing.T) {
	original := listenAndServeRadius
	t.Cleanup(func() { listenAndServeRadius = original })
	t.Setenv("radiusServerPort", "18120")
	t.Setenv("radiusServerEnabled", "true")
	t.Setenv("radiusSecret", "a-non-default-radius-secret")

	called := false
	listenAndServeRadius = func(server *radiuslib.PacketServer) error {
		called = true
		if server.Addr != "0.0.0.0:18120" {
			t.Fatalf("RADIUS address = %q", server.Addr)
		}
		return nil
	}
	StartRadiusServer()
	if !called {
		t.Fatal("valid RADIUS port did not reach listener")
	}
}

func TestRadiusListenerRequiresExplicitEnableAndNonDefaultSecret(t *testing.T) {
	original := listenAndServeRadius
	t.Cleanup(func() { listenAndServeRadius = original })
	called := false
	listenAndServeRadius = func(_ *radiuslib.PacketServer) error {
		called = true
		return nil
	}
	t.Setenv("radiusServerPort", "18120")

	for _, test := range []struct {
		name    string
		enabled string
		secret  string
	}{
		{name: "missing enable", enabled: "", secret: "a-non-default-radius-secret"},
		{name: "false enable", enabled: "false", secret: "a-non-default-radius-secret"},
		{name: "misspelled enable", enabled: "TRUE", secret: "a-non-default-radius-secret"},
		{name: "default secret", enabled: "true", secret: "secret"},
		{name: "empty secret", enabled: "true", secret: ""},
		{name: "short secret", enabled: "true", secret: "too-short"},
	} {
		t.Run(test.name, func(t *testing.T) {
			called = false
			t.Setenv("radiusServerEnabled", test.enabled)
			t.Setenv("radiusSecret", test.secret)
			StartRadiusServer()
			if called {
				t.Fatal("RADIUS listener started without explicit secure configuration")
			}
		})
	}
}

func resetAccessStatesForTest(t *testing.T) {
	t.Helper()
	stateMapMutex.Lock()
	StateMap = nil
	stateMapMutex.Unlock()
	t.Cleanup(func() {
		stateMapMutex.Lock()
		StateMap = nil
		stateMapMutex.Unlock()
	})
}

func TestAccessStateIsBoundToOrganizationAndUserAndConsumedOnFailure(t *testing.T) {
	resetAccessStatesForTest(t)
	now := time.Unix(1_750_000_000, 0)
	state, err := issueAccessState("org-a", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if consumeAccessState(state, "org-b", "alice", now) {
		t.Fatal("cross-organization RADIUS state was accepted")
	}
	if consumeAccessState(state, "org-a", "alice", now) {
		t.Fatal("state survived a failed cross-organization attempt")
	}

	state, err = issueAccessState("org-a", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if consumeAccessState(state, "org-a", "bob", now) {
		t.Fatal("cross-user RADIUS state was accepted")
	}
	if consumeAccessState("arbitrary-client-state", "org-a", "no-mfa-user", now) {
		t.Fatal("arbitrary state was accepted")
	}
}

func TestAccessStateIsOneTimeUnderConcurrency(t *testing.T) {
	resetAccessStatesForTest(t)
	now := time.Unix(1_750_000_000, 0)
	state, err := issueAccessState("org-a", "alice", now)
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 32
	start := make(chan struct{})
	var accepted atomic.Int32
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer waitGroup.Done()
			<-start
			if consumeAccessState(state, "org-a", "alice", now) {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted state consumptions = %d, want 1", accepted.Load())
	}
}

func TestExpiredAccessStateIsRejectedAndConsumed(t *testing.T) {
	resetAccessStatesForTest(t)
	now := time.Unix(1_750_000_000, 0)
	state, err := issueAccessState("org-a", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if consumeAccessState(state, "org-a", "alice", now.Add(StateExpiredTime+time.Second)) {
		t.Fatal("expired RADIUS state was accepted")
	}
	if consumeAccessState(state, "org-a", "alice", now) {
		t.Fatal("expired state survived its first presentation")
	}
}
