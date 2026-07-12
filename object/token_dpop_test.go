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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type recordingDPoPReplayStore struct {
	keys map[string]struct{}
	ttls []time.Duration
	uses int
}

func newRecordingDPoPReplayStore() *recordingDPoPReplayStore {
	return &recordingDPoPReplayStore{keys: map[string]struct{}{}}
}

func (store *recordingDPoPReplayStore) Use(key string, ttl time.Duration) (bool, error) {
	store.uses++
	store.ttls = append(store.ttls, ttl)
	if _, ok := store.keys[key]; ok {
		return false, nil
	}
	store.keys[key] = struct{}{}
	return true, nil
}

func useDPoPReplayStoreForTest(t *testing.T, store dpopReplayStore) {
	t.Helper()
	previousStore := globalDPoPReplayStore
	globalDPoPReplayStore = store
	t.Cleanup(func() {
		globalDPoPReplayStore = previousStore
	})
}

func makeDPoPProof(t *testing.T, jti, method, htu string, issuedAt time.Time) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	claims := DPoPProofClaims{
		Jti: jti,
		Htm: method,
		Htu: htu,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
	}
	proof := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	proof.Header["typ"] = "dpop+jwt"
	proof.Header["jwk"] = jose.JSONWebKey{Key: &privateKey.PublicKey}
	proofString, err := proof.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	return proofString
}

func TestNormalizeDPoPTargetURIOnlyNormalizesOrigin(t *testing.T) {
	normalized, err := normalizeDPoPTargetURI("HTTPS://ID.Example.COM:443/API/Resource?Key=Value")
	if err != nil {
		t.Fatalf("normalize target URI: %v", err)
	}
	if want := "https://id.example.com/API/Resource?Key=Value"; normalized != want {
		t.Fatalf("normalized target URI = %q, want %q", normalized, want)
	}

	for _, different := range []string{
		"https://id.example.com/api/Resource?Key=Value",
		"https://id.example.com/API/Resource?key=Value",
		"https://id.example.com/API/Resource?Key=value",
	} {
		other, err := normalizeDPoPTargetURI(different)
		if err != nil {
			t.Fatalf("normalize comparison URI %q: %v", different, err)
		}
		if other == normalized {
			t.Errorf("case-sensitive URI component was normalized away: %q", different)
		}
	}
}

func TestDPoPProofReplayCannotUseHostCaseVariant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newRecordingDPoPReplayStore()
	useDPoPReplayStoreForTest(t, store)
	proof := makeDPoPProof(t, "case-replay", "GET", "https://ID.Example.COM/API/resource", now)

	if _, err := validateDPoPProofAt(proof, "GET", "https://id.example.com:443/API/resource", "", now); err != nil {
		t.Fatalf("first proof use failed: %v", err)
	}
	if _, err := validateDPoPProofAt(proof, "GET", "https://Id.Example.Com/API/resource", "", now); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("case-variant replay error = %v, want replay rejection", err)
	}
	if store.uses != 2 {
		t.Fatalf("replay store uses = %d, want 2", store.uses)
	}
}

func TestDPoPProofRejectsPathQueryAndMethodCaseChanges(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newRecordingDPoPReplayStore()
	useDPoPReplayStoreForTest(t, store)

	tests := []struct {
		name     string
		proofHtm string
		proofHtu string
		method   string
		htu      string
	}{
		{name: "path", proofHtm: "GET", proofHtu: "https://id.example.com/API", method: "GET", htu: "https://id.example.com/api"},
		{name: "query-name", proofHtm: "GET", proofHtu: "https://id.example.com/API?Key=Value", method: "GET", htu: "https://id.example.com/API?key=Value"},
		{name: "query-value", proofHtm: "GET", proofHtu: "https://id.example.com/API?Key=Value", method: "GET", htu: "https://id.example.com/API?Key=value"},
		{name: "method", proofHtm: "GET", proofHtu: "https://id.example.com/API", method: "get", htu: "https://id.example.com/API"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			proof := makeDPoPProof(t, "case-"+test.name, test.proofHtm, test.proofHtu, now)
			if _, err := validateDPoPProofAt(proof, test.method, test.htu, "", now); err == nil {
				t.Fatal("case-variant proof was accepted")
			}
		})
	}
	if store.uses != 0 {
		t.Fatalf("invalid proofs reached replay store %d times", store.uses)
	}
}

func TestDPoPProofFutureSkewAndReplayTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newRecordingDPoPReplayStore()
	useDPoPReplayStoreForTest(t, store)

	tooFarFuture := makeDPoPProof(t, "future-rejected", "POST", "https://id.example.com/token", now.Add((dpopMaxFutureSkewSeconds+1)*time.Second))
	if _, err := validateDPoPProofAt(tooFarFuture, "POST", "https://id.example.com/token", "", now); err == nil || !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("future proof error = %v, want strict skew rejection", err)
	}
	if store.uses != 0 {
		t.Fatalf("future proof reached replay store %d times", store.uses)
	}

	acceptedFutureOffset := 20 * time.Second
	acceptedFuture := makeDPoPProof(t, "future-accepted", "POST", "https://id.example.com/token", now.Add(acceptedFutureOffset))
	if _, err := validateDPoPProofAt(acceptedFuture, "POST", "https://id.example.com/token", "", now); err != nil {
		t.Fatalf("proof within future skew failed: %v", err)
	}
	if len(store.ttls) != 1 {
		t.Fatalf("recorded replay TTLs = %d, want 1", len(store.ttls))
	}
	wantTtl := time.Duration(dpopMaxAgeSeconds)*time.Second + acceptedFutureOffset
	if store.ttls[0] != wantTtl {
		t.Fatalf("replay TTL = %s, want %s", store.ttls[0], wantTtl)
	}

	expired := makeDPoPProof(t, "expired", "POST", "https://id.example.com/token", now.Add(-time.Duration(dpopMaxAgeSeconds)*time.Second))
	if _, err := validateDPoPProofAt(expired, "POST", "https://id.example.com/token", "", now); err == nil || !strings.Contains(err.Error(), "outside the acceptable time window") {
		t.Fatalf("expired proof error = %v, want expiry rejection", err)
	}
}
