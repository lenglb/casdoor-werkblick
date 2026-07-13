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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/casdoor/casdoor/object"
)

const (
	providerStateSessionKey        = "providerStateTransactions"
	providerStateLifetime          = 10 * time.Minute
	providerStateNonceBytes        = 32
	providerStateMaxTransactions   = 256
	providerStateMaxConsumedClaims = 4096
)

var providerStateMethods = [...]string{"signin", "signup", "link"}

type providerStateTransaction struct {
	Nonce         string `json:"nonce"`
	ApplicationId string `json:"applicationId"`
	Provider      string `json:"provider"`
	Method        string `json:"method"`
	ExpiresAt     int64  `json:"expiresAt"`
}

type providerStateTransactionSet struct {
	Transactions []providerStateTransaction `json:"transactions"`
}

// consumedProviderStateStore closes the small race between reading a session
// transaction and persisting its deletion. The authoritative transaction stays
// in the server-side Beego session, while this bounded process-local claim set
// makes concurrent callbacks one-shot on a single Casdoor instance.
type consumedProviderStateStore struct {
	mu      sync.Mutex
	entries map[string]int64
}

var consumedProviderStates = consumedProviderStateStore{entries: map[string]int64{}}

func newProviderStateNonce() (string, error) {
	buffer := make([]byte, providerStateNonceBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate provider state nonce: %w", err)
	}
	// Lowercase hexadecimal is accepted even by short-state providers that
	// restrict state to alphanumeric characters (for example embedded clients).
	return hex.EncodeToString(buffer), nil
}

func parseProviderStateNonce(state string) (string, error) {
	if state == "" || len(state) > 8192 || strings.TrimSpace(state) != state {
		return "", fmt.Errorf("provider state is missing or malformed")
	}
	parts := strings.Split(state, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("provider state is malformed")
	}
	nonce := parts[0]
	decoded, err := hex.DecodeString(nonce)
	if err != nil || len(decoded) != providerStateNonceBytes || hex.EncodeToString(decoded) != nonce {
		return "", fmt.Errorf("provider state is malformed")
	}
	if len(parts) == 2 {
		if parts[1] == "" {
			return "", fmt.Errorf("provider state payload is missing")
		}
		payload, payloadErr := base64.RawURLEncoding.DecodeString(parts[1])
		if payloadErr != nil || len(payload) == 0 || base64.RawURLEncoding.EncodeToString(payload) != parts[1] {
			return "", fmt.Errorf("provider state payload is malformed")
		}
	}
	return nonce, nil
}

func pruneProviderStateTransactions(transactions []providerStateTransaction, now int64, limit int) []providerStateTransaction {
	if limit <= 0 {
		return nil
	}
	result := make([]providerStateTransaction, 0, len(transactions))
	for _, transaction := range transactions {
		if transaction.ExpiresAt > now {
			result = append(result, transaction)
		}
	}
	if len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

func removeProviderStateTransaction(transactions []providerStateTransaction, nonce string) ([]providerStateTransaction, providerStateTransaction, bool) {
	for index, transaction := range transactions {
		if subtle.ConstantTimeCompare([]byte(transaction.Nonce), []byte(nonce)) != 1 {
			continue
		}
		updated := make([]providerStateTransaction, 0, len(transactions)-1)
		updated = append(updated, transactions[:index]...)
		updated = append(updated, transactions[index+1:]...)
		return updated, transaction, true
	}
	return transactions, providerStateTransaction{}, false
}

func validateProviderStateTransaction(transaction providerStateTransaction, applicationId string, provider string, method string, now int64) error {
	if transaction.ExpiresAt <= now {
		return fmt.Errorf("provider state transaction has expired")
	}
	if subtle.ConstantTimeCompare([]byte(transaction.ApplicationId), []byte(applicationId)) != 1 ||
		subtle.ConstantTimeCompare([]byte(transaction.Provider), []byte(provider)) != 1 ||
		subtle.ConstantTimeCompare([]byte(transaction.Method), []byte(method)) != 1 {
		return fmt.Errorf("provider state transaction does not match the authentication request")
	}
	return nil
}

func (store *consumedProviderStateStore) claim(nonce string, expiresAt int64, now int64) bool {
	store.mu.Lock()
	defer store.mu.Unlock()

	for key, expiry := range store.entries {
		if expiry <= now {
			delete(store.entries, key)
		}
	}
	if _, exists := store.entries[nonce]; exists {
		return false
	}
	if len(store.entries) >= providerStateMaxConsumedClaims {
		oldestKey := ""
		oldestExpiry := int64(^uint64(0) >> 1)
		for key, expiry := range store.entries {
			if expiry < oldestExpiry {
				oldestKey = key
				oldestExpiry = expiry
			}
		}
		delete(store.entries, oldestKey)
	}
	store.entries[nonce] = expiresAt
	return true
}

func (store *consumedProviderStateStore) release(nonce string) {
	store.mu.Lock()
	delete(store.entries, nonce)
	store.mu.Unlock()
}

func (c *ApiController) getProviderStateTransactions() ([]providerStateTransaction, error) {
	value := c.GetSession(providerStateSessionKey)
	if value == nil {
		return nil, nil
	}
	serialized, ok := value.(string)
	if !ok || serialized == "" {
		return nil, fmt.Errorf("provider state session is invalid")
	}
	var transactionSet providerStateTransactionSet
	if err := json.Unmarshal([]byte(serialized), &transactionSet); err != nil {
		return nil, fmt.Errorf("decode provider state session: %w", err)
	}
	return transactionSet.Transactions, nil
}

func (c *ApiController) setProviderStateTransactions(transactions []providerStateTransaction) error {
	serialized, err := json.Marshal(providerStateTransactionSet{Transactions: transactions})
	if err != nil {
		return fmt.Errorf("encode provider state session: %w", err)
	}
	if err = c.SetSession(providerStateSessionKey, string(serialized)); err != nil {
		return fmt.Errorf("store provider state session: %w", err)
	}
	return nil
}

func providerStateKey(provider string, method string) string {
	return provider + ":" + method
}

func issueProviderStateTransactions(application *object.Application, existing []providerStateTransaction, now int64, nonceGenerator func() (string, error)) ([]providerStateTransaction, map[string]string, error) {
	if application == nil {
		return existing, nil, nil
	}
	existing = pruneProviderStateTransactions(existing, now, providerStateMaxTransactions)

	providerCount := 0
	for _, item := range application.Providers {
		if item != nil && item.Provider != nil &&
			(item.Provider.Category == "OAuth" || item.Provider.Category == "Web3") {
			providerCount++
		}
	}
	newTransactionCount := providerCount * len(providerStateMethods)
	if newTransactionCount == 0 {
		return existing, map[string]string{}, nil
	}
	if newTransactionCount > providerStateMaxTransactions {
		return nil, nil, fmt.Errorf("application has too many federated providers")
	}
	if keep := providerStateMaxTransactions - newTransactionCount; len(existing) > keep {
		existing = existing[len(existing)-keep:]
	}

	states := make(map[string]string, newTransactionCount)
	expiresAt := now + int64(providerStateLifetime/time.Second)
	for _, item := range application.Providers {
		if item == nil || item.Provider == nil ||
			(item.Provider.Category != "OAuth" && item.Provider.Category != "Web3") {
			continue
		}
		for _, method := range providerStateMethods {
			nonce, err := nonceGenerator()
			if err != nil {
				return nil, nil, err
			}
			existing = append(existing, providerStateTransaction{
				Nonce:         nonce,
				ApplicationId: application.GetId(),
				Provider:      item.Provider.Name,
				Method:        method,
				ExpiresAt:     expiresAt,
			})
			states[providerStateKey(item.Provider.Name, method)] = nonce
		}
	}
	return existing, states, nil
}

// attachProviderStates issues one transaction for each supported action of
// every visible OAuth/Web3 provider. Keeping these nonces in the application
// response preserves the synchronous provider-link rendering API.
func (c *ApiController) attachProviderStates(application *object.Application) error {
	if application == nil {
		return nil
	}

	existing, err := c.getProviderStateTransactions()
	if err != nil {
		return err
	}
	existing, states, err := issueProviderStateTransactions(application, existing, time.Now().Unix(), newProviderStateNonce)
	if err != nil {
		return err
	}
	if err = c.setProviderStateTransactions(existing); err != nil {
		return err
	}
	application.ProviderStates = states
	return nil
}

// consumeProviderState validates and removes the transaction before any code
// is exchanged with the external identity provider. Application, provider and
// action are exact bindings; no static configured state or app-name fallback
// is accepted.
func (c *ApiController) consumeProviderState(state string, applicationId string, provider string, method string) error {
	nonce, err := parseProviderStateNonce(state)
	if err != nil {
		return err
	}
	transactions, err := c.getProviderStateTransactions()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	transactions, transaction, found := removeProviderStateTransaction(transactions, nonce)
	if !found {
		return fmt.Errorf("provider state transaction is missing or already consumed")
	}

	if !consumedProviderStates.claim(nonce, transaction.ExpiresAt, now) {
		return fmt.Errorf("provider state transaction is already consumed")
	}
	if err = c.setProviderStateTransactions(pruneProviderStateTransactions(transactions, now, providerStateMaxTransactions)); err != nil {
		consumedProviderStates.release(nonce)
		return err
	}

	return validateProviderStateTransaction(transaction, applicationId, provider, method, now)
}
