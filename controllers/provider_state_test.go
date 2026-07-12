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

package controllers

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestProviderStateNonceIsCryptographicAndStrictlyParsed(t *testing.T) {
	nonce, err := newProviderStateNonce()
	if err != nil {
		t.Fatalf("newProviderStateNonce() error = %v", err)
	}
	if len(nonce) != 64 {
		t.Fatalf("nonce length = %d, want 64", len(nonce))
	}

	for _, state := range []string{nonce, nonce + ".cGF5bG9hZA"} {
		got, parseErr := parseProviderStateNonce(state)
		if parseErr != nil {
			t.Fatalf("parseProviderStateNonce(%q) error = %v", state, parseErr)
		}
		if got != nonce {
			t.Fatalf("parsed nonce = %q, want %q", got, nonce)
		}
	}

	for _, state := range []string{"", "app-built-in", nonce + ".", nonce + ".invalid!", nonce + ".cGF5bG9hZA.extra", " " + nonce, strings.Repeat("a", 63), strings.Repeat("A", 64), nonce + "." + strings.Repeat("a", 8192)} {
		if _, parseErr := parseProviderStateNonce(state); parseErr == nil {
			t.Fatalf("parseProviderStateNonce(%q) unexpectedly succeeded", state)
		}
	}
}

func TestProviderStateTransactionIsOneShotAndExactlyBound(t *testing.T) {
	now := int64(1_000)
	transaction := providerStateTransaction{
		Nonce:         strings.Repeat("a", 64),
		ApplicationId: "admin/app",
		Provider:      "github",
		Method:        "signup",
		ExpiresAt:     now + 60,
	}
	transactions := []providerStateTransaction{transaction}

	remaining, consumed, found := removeProviderStateTransaction(transactions, transaction.Nonce)
	if !found || len(remaining) != 0 || consumed != transaction {
		t.Fatalf("transaction was not consumed exactly once: found=%v remaining=%d consumed=%+v", found, len(remaining), consumed)
	}
	if _, _, found = removeProviderStateTransaction(remaining, transaction.Nonce); found {
		t.Fatal("consumed transaction was accepted a second time")
	}
	if err := validateProviderStateTransaction(consumed, "admin/app", "github", "signup", now); err != nil {
		t.Fatalf("exact transaction binding rejected: %v", err)
	}

	for _, test := range []struct {
		applicationId string
		provider      string
		method        string
		now           int64
	}{
		{applicationId: "admin/other", provider: "github", method: "signup", now: now},
		{applicationId: "admin/app", provider: "google", method: "signup", now: now},
		{applicationId: "admin/app", provider: "github", method: "link", now: now},
		{applicationId: "admin/app", provider: "github", method: "signup", now: now + 60},
	} {
		if err := validateProviderStateTransaction(consumed, test.applicationId, test.provider, test.method, test.now); err == nil {
			t.Fatalf("mismatched/expired transaction unexpectedly accepted: %+v", test)
		}
	}
}

func TestProviderStateTransactionCleanupIsBounded(t *testing.T) {
	now := int64(2_000)
	transactions := []providerStateTransaction{
		{Nonce: "expired", ExpiresAt: now},
		{Nonce: "oldest", ExpiresAt: now + 1},
		{Nonce: "middle", ExpiresAt: now + 2},
		{Nonce: "newest", ExpiresAt: now + 3},
	}

	got := pruneProviderStateTransactions(transactions, now, 2)
	if len(got) != 2 || got[0].Nonce != "middle" || got[1].Nonce != "newest" {
		t.Fatalf("bounded cleanup = %+v, want middle and newest", got)
	}
}

func TestProviderStatesAreIssuedForEveryFederatedMethodAndBoundToApplication(t *testing.T) {
	application := &object.Application{
		Owner: "admin",
		Name:  "app",
		Providers: []*object.ProviderItem{
			{Provider: &object.Provider{Name: "github", Category: "OAuth"}},
			{Provider: &object.Provider{Name: "wallet", Category: "Web3"}},
			{Provider: &object.Provider{Name: "saml", Category: "SAML"}},
		},
	}
	sequence := 0
	transactions, states, err := issueProviderStateTransactions(application, nil, 10_000, func() (string, error) {
		sequence++
		return fmt.Sprintf("nonce-%d", sequence), nil
	})
	if err != nil {
		t.Fatalf("issueProviderStateTransactions() error = %v", err)
	}
	if len(transactions) != 6 || len(states) != 6 {
		t.Fatalf("issued transactions=%d states=%d, want six OAuth/Web3 method bindings", len(transactions), len(states))
	}
	for _, provider := range []string{"github", "wallet"} {
		for _, method := range providerStateMethods {
			if states[providerStateKey(provider, method)] == "" {
				t.Fatalf("missing state for %s/%s", provider, method)
			}
		}
	}
	if _, ok := states[providerStateKey("saml", "signup")]; ok {
		t.Fatal("SAML provider unexpectedly received an OAuth state transaction")
	}
	for _, transaction := range transactions {
		if transaction.ApplicationId != "admin/app" || transaction.ExpiresAt != 10_600 {
			t.Fatalf("transaction is not exactly application/TTL bound: %+v", transaction)
		}
	}
}

func TestConsumedProviderStateClaimIsAtomic(t *testing.T) {
	store := consumedProviderStateStore{entries: map[string]int64{}}
	start := make(chan struct{})
	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			if store.claim("nonce", 20, 10) {
				successes.Add(1)
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent claims succeeded %d times, want exactly once", successes.Load())
	}
	if !store.claim("nonce", 30, 20) {
		t.Fatal("expired claim was not cleaned up")
	}
}
