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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClaimPendingAuthenticationTransactionOnce(t *testing.T) {
	transactionId := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	defer consumedAuthenticationTransactions.Delete(transactionId)

	const attempts = 32
	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer waitGroup.Done()
			if claimPendingAuthenticationTransaction(transactionId, time.Now().Add(time.Minute).Unix(), time.Now().Unix()) {
				successes.Add(1)
			}
		}()
	}
	waitGroup.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("successful claims = %d, want 1", got)
	}
}

func TestClaimPendingAuthenticationTransactionCleansExpiredClaim(t *testing.T) {
	transactionId := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	defer consumedAuthenticationTransactions.Delete(transactionId)

	now := time.Now().Unix()
	consumedAuthenticationTransactions.Store(transactionId, now-1)
	if !claimPendingAuthenticationTransaction(transactionId, now+60, now) {
		t.Fatal("claimPendingAuthenticationTransaction() did not replace an expired claim")
	}
}
