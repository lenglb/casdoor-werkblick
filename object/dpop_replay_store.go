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
	dpopReplayRedisPrefix  = "casdoor:dpop_replay:"
	dpopReplayCleanupLimit = 64
)

type dpopReplayStore interface {
	Use(key string, ttl time.Duration) (bool, error)
}

type memoryDPoPReplayStore struct {
	mutex   sync.Mutex
	expires map[string]time.Time
	queue   dpopReplayExpiryHeap
	now     func() time.Time
}

type dpopReplayExpiry struct {
	key       string
	expiresAt time.Time
}

type dpopReplayExpiryHeap []dpopReplayExpiry

func (expiryHeap dpopReplayExpiryHeap) Len() int { return len(expiryHeap) }

func (expiryHeap dpopReplayExpiryHeap) Less(i, j int) bool {
	return expiryHeap[i].expiresAt.Before(expiryHeap[j].expiresAt)
}

func (expiryHeap dpopReplayExpiryHeap) Swap(i, j int) {
	expiryHeap[i], expiryHeap[j] = expiryHeap[j], expiryHeap[i]
}

func (expiryHeap *dpopReplayExpiryHeap) Push(value interface{}) {
	*expiryHeap = append(*expiryHeap, value.(dpopReplayExpiry))
}

func (expiryHeap *dpopReplayExpiryHeap) Pop() interface{} {
	old := *expiryHeap
	lastIndex := len(old) - 1
	value := old[lastIndex]
	*expiryHeap = old[:lastIndex]
	return value
}

func newMemoryDPoPReplayStore() *memoryDPoPReplayStore {
	return &memoryDPoPReplayStore{
		expires: map[string]time.Time{},
		queue:   dpopReplayExpiryHeap{},
		now:     time.Now,
	}
}

func (store *memoryDPoPReplayStore) Use(key string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, fmt.Errorf("DPoP replay marker TTL must be greater than zero")
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	now := store.now()
	store.cleanupExpired(now, dpopReplayCleanupLimit)
	if expiresAt, ok := store.expires[key]; ok && expiresAt.After(now) {
		return false, nil
	}

	expiresAt := now.Add(ttl)
	store.expires[key] = expiresAt
	heap.Push(&store.queue, dpopReplayExpiry{key: key, expiresAt: expiresAt})
	return true, nil
}

func (store *memoryDPoPReplayStore) cleanupExpired(now time.Time, limit int) {
	for cleaned := 0; cleaned < limit && store.queue.Len() > 0; cleaned++ {
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

type redisDPoPReplayStore struct {
	client *redis.Client
}

func (store *redisDPoPReplayStore) Use(key string, ttl time.Duration) (bool, error) {
	return store.client.SetNX(context.Background(), dpopReplayRedisPrefix+key, "1", ttl).Result()
}

type unavailableDPoPReplayStore struct {
	err error
}

func (store *unavailableDPoPReplayStore) Use(string, time.Duration) (bool, error) {
	return false, store.err
}

var globalDPoPReplayStore dpopReplayStore = newMemoryDPoPReplayStore()

func InitDPoPReplayStore() {
	endpoint := conf.GetConfigString("redisEndpoint")
	if endpoint == "" {
		return
	}

	client, err := newRedisClient(endpoint)
	if err != nil {
		globalDPoPReplayStore = &unavailableDPoPReplayStore{err: fmt.Errorf("DPoP replay store is unavailable")}
		logs.Error("dpop_replay_store: failed to connect to Redis (%s), DPoP requests will fail closed (error type: %T)", sanitizeRedisEndpointForLog(endpoint), err)
		return
	}
	globalDPoPReplayStore = &redisDPoPReplayStore{client: client}
	logs.Info("dpop_replay_store: using Redis backend at %s", sanitizeRedisEndpointForLog(endpoint))
}

func useDPoPProofOnce(key string, ttl time.Duration) error {
	used, err := globalDPoPReplayStore.Use(key, ttl)
	if err != nil {
		return fmt.Errorf("store DPoP proof replay marker: %w", err)
	}
	if !used {
		return fmt.Errorf("DPoP proof has already been used")
	}
	return nil
}
