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
	"container/heap"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/conf"
	"github.com/redis/go-redis/v9"
)

const (
	clientAssertionReplayRedisPrefix = "casdoor:client_assertion_replay:"
	clientAssertionReplayMaxEntries  = 10000
)

type clientAssertionReplayStore interface {
	Use(key string, ttl time.Duration) (bool, error)
}

type memoryClientAssertionReplayStore struct {
	mutex      sync.Mutex
	expires    map[string]time.Time
	queue      clientAssertionReplayExpiryHeap
	now        func() time.Time
	maxEntries int
}

type clientAssertionReplayExpiry struct {
	key       string
	expiresAt time.Time
}

type clientAssertionReplayExpiryHeap []clientAssertionReplayExpiry

func (expiryHeap clientAssertionReplayExpiryHeap) Len() int { return len(expiryHeap) }

func (expiryHeap clientAssertionReplayExpiryHeap) Less(i, j int) bool {
	return expiryHeap[i].expiresAt.Before(expiryHeap[j].expiresAt)
}

func (expiryHeap clientAssertionReplayExpiryHeap) Swap(i, j int) {
	expiryHeap[i], expiryHeap[j] = expiryHeap[j], expiryHeap[i]
}

func (expiryHeap *clientAssertionReplayExpiryHeap) Push(value interface{}) {
	*expiryHeap = append(*expiryHeap, value.(clientAssertionReplayExpiry))
}

func (expiryHeap *clientAssertionReplayExpiryHeap) Pop() interface{} {
	old := *expiryHeap
	lastIndex := len(old) - 1
	value := old[lastIndex]
	*expiryHeap = old[:lastIndex]
	return value
}

func newMemoryClientAssertionReplayStore(maxEntries int) *memoryClientAssertionReplayStore {
	return &memoryClientAssertionReplayStore{
		expires:    map[string]time.Time{},
		queue:      clientAssertionReplayExpiryHeap{},
		now:        time.Now,
		maxEntries: maxEntries,
	}
}

func (store *memoryClientAssertionReplayStore) Use(key string, ttl time.Duration) (bool, error) {
	if key == "" || ttl <= 0 {
		return false, fmt.Errorf("client assertion replay marker key and TTL are required")
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	now := store.now()
	store.cleanupExpired(now)
	if expiresAt, ok := store.expires[key]; ok && expiresAt.After(now) {
		return false, nil
	}
	if store.maxEntries <= 0 || len(store.expires) >= store.maxEntries {
		// Never evict a still-valid marker: that would turn resource pressure into
		// a replay bypass. Capacity exhaustion therefore fails closed.
		return false, fmt.Errorf("client assertion replay store capacity exhausted")
	}

	expiresAt := now.Add(ttl)
	store.expires[key] = expiresAt
	heap.Push(&store.queue, clientAssertionReplayExpiry{key: key, expiresAt: expiresAt})
	return true, nil
}

func (store *memoryClientAssertionReplayStore) cleanupExpired(now time.Time) {
	for store.queue.Len() > 0 {
		next := store.queue[0]
		if next.expiresAt.After(now) {
			return
		}
		heap.Pop(&store.queue)
		if currentExpiry, ok := store.expires[next.key]; ok && currentExpiry.Equal(next.expiresAt) {
			delete(store.expires, next.key)
		}
	}
}

type redisClientAssertionReplayStore struct {
	client *redis.Client
}

func (store *redisClientAssertionReplayStore) Use(key string, ttl time.Duration) (bool, error) {
	return store.client.SetNX(context.Background(), clientAssertionReplayRedisPrefix+key, "1", ttl).Result()
}

type unavailableClientAssertionReplayStore struct {
	err error
}

func (store *unavailableClientAssertionReplayStore) Use(string, time.Duration) (bool, error) {
	return false, store.err
}

var globalClientAssertionReplayStore clientAssertionReplayStore = newMemoryClientAssertionReplayStore(clientAssertionReplayMaxEntries)

func InitClientAssertionReplayStore() {
	endpoint := conf.GetConfigString("redisEndpoint")
	if endpoint == "" {
		return
	}

	client, err := newRedisClient(endpoint)
	if err != nil {
		globalClientAssertionReplayStore = &unavailableClientAssertionReplayStore{err: fmt.Errorf("client assertion replay store is unavailable")}
		logs.Error("client_assertion_replay_store: failed to connect to Redis (%s), private_key_jwt requests will fail closed (error type: %T)", sanitizeRedisEndpointForLog(endpoint), err)
		return
	}
	globalClientAssertionReplayStore = &redisClientAssertionReplayStore{client: client}
	logs.Info("client_assertion_replay_store: using Redis backend at %s", sanitizeRedisEndpointForLog(endpoint))
}

func useClientAssertionOnce(key string, ttl time.Duration) error {
	used, err := globalClientAssertionReplayStore.Use(key, ttl)
	if err != nil {
		return fmt.Errorf("store client assertion replay marker: %w", err)
	}
	if !used {
		return fmt.Errorf("client assertion has already been used")
	}
	return nil
}
