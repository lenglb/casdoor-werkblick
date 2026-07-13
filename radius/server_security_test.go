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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
	radiuslib "layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type recordingRadiusResponseWriter struct {
	packets []*radiuslib.Packet
}

func (writer *recordingRadiusResponseWriter) Write(packet *radiuslib.Packet) error {
	writer.packets = append(writer.packets, packet)
	return nil
}

func newRadiusAccessRequest(t *testing.T, organization string, username string, password string, state string) *radiuslib.Request {
	t.Helper()
	packet := radiuslib.New(radiuslib.CodeAccessRequest, []byte("unit-test-radius-secret"))
	if err := rfc2865.Class_SetString(packet, organization); err != nil {
		t.Fatal(err)
	}
	if err := rfc2865.UserName_SetString(packet, username); err != nil {
		t.Fatal(err)
	}
	if err := rfc2865.UserPassword_SetString(packet, password); err != nil {
		t.Fatal(err)
	}
	if state != "" {
		if err := rfc2865.State_SetString(packet, state); err != nil {
			t.Fatal(err)
		}
	}
	return &radiuslib.Request{Packet: packet}
}

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

func TestPendingAccessStateStoreIsBoundedAndFailsClosed(t *testing.T) {
	resetAccessStatesForTest(t)
	now := time.Unix(1_750_000_000, 0)
	stateMapMutex.Lock()
	StateMap = make(map[string]AccessStateContent, MaxPendingAccessStates)
	for index := 0; index < MaxPendingAccessStates; index++ {
		StateMap[fmt.Sprintf("state-%d", index)] = AccessStateContent{
			ExpiredAt: now.Add(StateExpiredTime),
			Owner:     "org-a",
			User:      "alice",
		}
	}
	stateMapMutex.Unlock()

	if state, err := issueAccessState("org-a", "alice", now); err == nil || state != "" {
		t.Fatalf("full RADIUS state store issued challenge (%q, %v)", state, err)
	}
}

func TestMfaPasswordStepWritesExactlyOneChallengeAndNeverAccepts(t *testing.T) {
	resetAccessStatesForTest(t)
	now := time.Unix(1_750_000_000, 0)
	user := &object.User{Owner: "org-a", Name: "alice", TotpSecret: "JBSWY3DPEHPK3PXP"}
	dependencies := accessRequestDependencies{
		checkUserPassword: func(organization string, username string, password string, lang string) (*object.User, error) {
			if organization != user.Owner || username != user.Name || password != "correct-password" || lang != "en" {
				return nil, fmt.Errorf("unexpected password check")
			}
			return user, nil
		},
		getUser: func(id string) (*object.User, error) {
			return nil, fmt.Errorf("unexpected second-step user lookup for %s", id)
		},
		now: func() time.Time { return now },
	}

	writer := &recordingRadiusResponseWriter{}
	handleAccessRequestWithDependencies(
		writer,
		newRadiusAccessRequest(t, user.Owner, user.Name, "correct-password", ""),
		dependencies,
	)

	if len(writer.packets) != 1 {
		t.Fatalf("RADIUS password step wrote %d packets, want exactly one", len(writer.packets))
	}
	if writer.packets[0].Code != radiuslib.CodeAccessChallenge {
		t.Fatalf("RADIUS password step response = %v, want Access-Challenge", writer.packets[0].Code)
	}
	if state := rfc2865.State_GetString(writer.packets[0]); state == "" {
		t.Fatal("RADIUS Access-Challenge omitted the one-time MFA state")
	}
	if reflectedPassword := rfc2865.UserPassword_Get(writer.packets[0]); len(reflectedPassword) != 0 {
		t.Fatal("RADIUS Access-Challenge reflected the request's password attribute")
	}
}

func TestMfaOtpFailureWritesExactlyOneRejectAndNeverAccepts(t *testing.T) {
	resetAccessStatesForTest(t)
	now := time.Unix(1_750_000_000, 0)
	user := &object.User{Owner: "org-a", Name: "alice", TotpSecret: "JBSWY3DPEHPK3PXP"}
	state, err := issueAccessState(user.Owner, user.Name, now)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := accessRequestDependencies{
		checkUserPassword: func(organization string, username string, password string, lang string) (*object.User, error) {
			return nil, fmt.Errorf("password verification must not run during the OTP step")
		},
		getUser: func(id string) (*object.User, error) {
			if id != user.GetId() {
				return nil, fmt.Errorf("unexpected user id %q", id)
			}
			return user, nil
		},
		now: func() time.Time { return now },
	}

	writer := &recordingRadiusResponseWriter{}
	handleAccessRequestWithDependencies(
		writer,
		newRadiusAccessRequest(t, user.Owner, user.Name, "not-a-six-digit-code", state),
		dependencies,
	)

	if len(writer.packets) != 1 {
		t.Fatalf("RADIUS OTP failure wrote %d packets, want exactly one", len(writer.packets))
	}
	if writer.packets[0].Code != radiuslib.CodeAccessReject {
		t.Fatalf("RADIUS OTP failure response = %v, want Access-Reject", writer.packets[0].Code)
	}
	if consumeAccessState(state, user.Owner, user.Name, now) {
		t.Fatal("failed RADIUS OTP left its one-time state replayable")
	}
}

func TestMfaOtpStepRevalidatesDisabledUserBeforeVerification(t *testing.T) {
	resetAccessStatesForTest(t)
	now := time.Unix(1_750_000_000, 0)
	user := &object.User{
		Owner:       "org-a",
		Name:        "alice",
		TotpSecret:  "JBSWY3DPEHPK3PXP",
		IsForbidden: true,
	}
	state, err := issueAccessState(user.Owner, user.Name, now)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := accessRequestDependencies{
		checkUserPassword: func(organization string, username string, password string, lang string) (*object.User, error) {
			return nil, fmt.Errorf("password verification must not run during the OTP step")
		},
		getUser: func(id string) (*object.User, error) { return user, nil },
		now:     func() time.Time { return now },
	}

	writer := &recordingRadiusResponseWriter{}
	handleAccessRequestWithDependencies(
		writer,
		newRadiusAccessRequest(t, user.Owner, user.Name, "000000", state),
		dependencies,
	)

	if len(writer.packets) != 1 || writer.packets[0].Code != radiuslib.CodeAccessReject {
		t.Fatalf("disabled RADIUS user responses = %#v, want one Access-Reject", writer.packets)
	}
}
