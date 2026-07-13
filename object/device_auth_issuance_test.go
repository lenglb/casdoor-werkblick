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

package object

import (
	"sync"
	"testing"
	"time"
)

func approvedDeviceAuthCache(now time.Time) DeviceAuthCache {
	return DeviceAuthCache{
		UserSignIn:    true,
		UserName:      "alice",
		ApplicationId: "admin/device-app",
		ClientId:      "device-client",
		Scope:         "openid profile",
		RequestAt:     now,
		Status:        DeviceAuthStatusApproved,
		ExpiresIn:     120,
		AuthenticationContext: AuthenticationContext{
			Subject:  "org/alice",
			AuthTime: now.Unix(),
			Amr:      []string{"pwd", "otp"},
		},
	}
}

func TestClaimDeviceAuthTokenIssuanceAllowsExactlyOneConcurrentWinner(t *testing.T) {
	store := &memoryDeviceAuthStore{}
	now := time.Now()
	store.Store("device-code", approvedDeviceAuthCache(now))

	const pollers = 128
	start := make(chan struct{})
	results := make(chan DeviceAuthTokenClaimResult, pollers)
	var ready sync.WaitGroup
	var done sync.WaitGroup
	ready.Add(pollers)
	done.Add(pollers)
	for i := 0; i < pollers; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			_, result := claimDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client", now.Add(time.Second))
			results <- result
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	close(results)

	claimed := 0
	for result := range results {
		switch result {
		case DeviceAuthTokenClaimed:
			claimed++
		case DeviceAuthTokenIssuanceInProgress:
		default:
			t.Errorf("concurrent claim returned %q, want claimed or token_issuing", result)
		}
	}
	if claimed != 1 {
		t.Fatalf("concurrent claims produced %d winners, want exactly 1", claimed)
	}

	value, ok := store.Load("device-code")
	if !ok {
		t.Fatal("claimed device code disappeared from store")
	}
	if status := value.(DeviceAuthCache).Status; status != DeviceAuthStatusTokenIssuing {
		t.Fatalf("status after concurrent claims = %q, want %q", status, DeviceAuthStatusTokenIssuing)
	}
	if !completeDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client") {
		t.Fatal("winning issuance could not be completed")
	}
	if completeDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client") {
		t.Fatal("completed issuance was accepted a second time")
	}
	if _, result := claimDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client", now.Add(2*time.Second)); result != DeviceAuthTokenAlreadyIssued {
		t.Fatalf("claim after completion = %q, want %q", result, DeviceAuthTokenAlreadyIssued)
	}
}

func TestClaimDeviceAuthTokenIssuanceEnforcesExactBinding(t *testing.T) {
	store := &memoryDeviceAuthStore{}
	now := time.Now()
	store.Store("device-code", approvedDeviceAuthCache(now))

	tests := []struct {
		name          string
		applicationId string
		clientId      string
	}{
		{name: "different application", applicationId: "admin/other-app", clientId: "device-client"},
		{name: "different client", applicationId: "admin/device-app", clientId: "other-client"},
		{name: "empty application", applicationId: "", clientId: "device-client"},
		{name: "empty client", applicationId: "admin/device-app", clientId: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, result := claimDeviceAuthTokenIssuance(store, "device-code", tc.applicationId, tc.clientId, now.Add(time.Second))
			want := DeviceAuthTokenBindingMismatch
			if tc.applicationId == "" || tc.clientId == "" {
				want = DeviceAuthTokenInvalid
			}
			if result != want {
				t.Fatalf("claim result = %q, want %q", result, want)
			}
		})
	}

	value, _ := store.Load("device-code")
	if status := value.(DeviceAuthCache).Status; status != DeviceAuthStatusApproved {
		t.Fatalf("binding mismatch changed status to %q", status)
	}
	if _, result := claimDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client", now.Add(time.Second)); result != DeviceAuthTokenClaimed {
		t.Fatalf("correctly bound claim = %q, want %q", result, DeviceAuthTokenClaimed)
	}
}

func TestRollbackDeviceAuthTokenIssuanceAllowsSafeRetry(t *testing.T) {
	store := &memoryDeviceAuthStore{}
	now := time.Now()
	store.Store("device-code", approvedDeviceAuthCache(now))

	if _, result := claimDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client", now.Add(time.Second)); result != DeviceAuthTokenClaimed {
		t.Fatalf("first claim = %q, want %q", result, DeviceAuthTokenClaimed)
	}
	if rollbackDeviceAuthTokenIssuance(store, "device-code", "admin/other-app", "device-client") {
		t.Fatal("rollback accepted a different application binding")
	}
	if rollbackDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "other-client") {
		t.Fatal("rollback accepted a different client binding")
	}
	if !rollbackDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client") {
		t.Fatal("correctly bound rollback failed")
	}
	if _, result := claimDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client", now.Add(2*time.Second)); result != DeviceAuthTokenClaimed {
		t.Fatalf("claim after rollback = %q, want %q", result, DeviceAuthTokenClaimed)
	}
}

func TestClaimDeviceAuthTokenIssuanceUsesConfiguredExpiry(t *testing.T) {
	store := &memoryDeviceAuthStore{}
	now := time.Now()
	cache := approvedDeviceAuthCache(now)
	cache.ExpiresIn = 5
	store.Store("device-code", cache)

	if _, result := claimDeviceAuthTokenIssuance(store, "device-code", "admin/device-app", "device-client", now.Add(5*time.Second)); result != DeviceAuthTokenExpired {
		t.Fatalf("claim at expiry boundary = %q, want %q", result, DeviceAuthTokenExpired)
	}
	value, _ := store.Load("device-code")
	if status := value.(DeviceAuthCache).Status; status != DeviceAuthStatusApproved {
		t.Fatalf("expired claim changed status to %q", status)
	}
}
