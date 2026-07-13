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
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDPoPReplayStoreAcceptsProofExactlyOnce(t *testing.T) {
	previousStore := globalDPoPReplayStore
	globalDPoPReplayStore = newMemoryDPoPReplayStore()
	t.Cleanup(func() {
		globalDPoPReplayStore = previousStore
	})

	if err := useDPoPProofOnce("proof-key", time.Minute); err != nil {
		t.Fatalf("first proof use failed: %v", err)
	}
	if err := useDPoPProofOnce("proof-key", time.Minute); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("second proof use error = %v, want replay rejection", err)
	}
	if err := useDPoPProofOnce("different-proof-key", time.Minute); err != nil {
		t.Fatalf("different proof was rejected: %v", err)
	}
}

func TestMemoryDPoPReplayStoreExpiresMarkers(t *testing.T) {
	store := newMemoryDPoPReplayStore()
	now := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return now }
	if used, err := store.Use("proof-key", time.Minute); err != nil || !used {
		t.Fatalf("first Use() = (%v, %v)", used, err)
	}

	now = now.Add(time.Minute + time.Second)

	if used, err := store.Use("proof-key", time.Minute); err != nil || !used {
		t.Fatalf("Use() after expiry = (%v, %v), want accepted", used, err)
	}
}

func TestMemoryDPoPReplayStoreBoundsCleanupPerRequest(t *testing.T) {
	store := newMemoryDPoPReplayStore()
	now := time.Unix(1_700_000_000, 0)
	store.now = func() time.Time { return now }

	totalExpired := dpopReplayCleanupLimit + 10
	for i := 0; i < totalExpired; i++ {
		if used, err := store.Use(fmt.Sprintf("expired-%d", i), time.Second); err != nil || !used {
			t.Fatalf("seed Use(%d) = (%v, %v)", i, used, err)
		}
	}

	now = now.Add(2 * time.Second)
	if used, err := store.Use("fresh", time.Minute); err != nil || !used {
		t.Fatalf("fresh Use() = (%v, %v)", used, err)
	}

	if got, want := len(store.expires), totalExpired-dpopReplayCleanupLimit+1; got != want {
		t.Fatalf("entries after bounded cleanup = %d, want %d", got, want)
	}
}

func TestMemoryDPoPReplayStoreRejectsNonPositiveTTL(t *testing.T) {
	store := newMemoryDPoPReplayStore()
	if used, err := store.Use("proof-key", 0); err == nil || used {
		t.Fatalf("Use() with zero TTL = (%v, %v), want rejection", used, err)
	}
}
