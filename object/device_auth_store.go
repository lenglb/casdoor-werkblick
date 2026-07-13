// Copyright 2025 The Casdoor Authors. All Rights Reserved.
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
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/conf"
	"github.com/redis/go-redis/v9"
)

// deviceAuthStore provides atomic transient-state operations for the device
// authorization flow. The default implementation is in-memory; when
// redisEndpoint is configured, Redis coordinates multiple Casdoor replicas.
type deviceAuthStore interface {
	Load(key any) (any, bool)
	Store(key, value any)
	Delete(key any)
	LoadAndDelete(key any) (any, bool)
	CompareAndSwapStatus(key any, applicationId string, clientId string, oldStatus string, newStatus string) (DeviceAuthCache, bool)
	Range(f func(key, value any) bool)
}

const deviceAuthRedisPrefix = "casdoor:device_auth:"

// InitDeviceAuthStore switches DeviceAuthMap to a Redis-backed store when redisEndpoint is
// configured. It must be called after configuration is loaded and before serving requests.
// On failure it logs a warning and keeps the default in-memory store.
func InitDeviceAuthStore() {
	endpoint := conf.GetConfigString("redisEndpoint")
	if endpoint == "" {
		return
	}

	client, err := newRedisClient(endpoint)
	if err != nil {
		logs.Warn("device_auth_store: failed to connect to Redis (%s), falling back to in-memory store (error type: %T)", sanitizeRedisEndpointForLog(endpoint), err)
		return
	}

	DeviceAuthMap = &redisDeviceAuthStore{client: client}
	logs.Info("device_auth_store: using Redis backend at %s", sanitizeRedisEndpointForLog(endpoint))
}

// sanitizeRedisEndpointForLog retains only the address portion of Casdoor's
// host:port[,db[,password]] Redis setting. It also strips URL-style user info
// defensively so credentials can never be copied into application logs.
func sanitizeRedisEndpointForLog(endpoint string) string {
	address := strings.TrimSpace(endpoint)
	if separator := strings.Index(address, ","); separator >= 0 {
		address = strings.TrimSpace(address[:separator])
	}
	if userInfo := strings.LastIndex(address, "@"); userInfo >= 0 {
		address = address[userInfo+1:]
	}
	if address == "" {
		return "configured endpoint"
	}
	return address
}

// newRedisClient parses the same "host:port[,db[,password]]" format that the beego session
// Redis provider uses, so users do not need a separate configuration key.
func newRedisClient(endpoint string) (*redis.Client, error) {
	addr := endpoint
	db := 0
	password := ""

	if i := strings.Index(endpoint, ","); i >= 0 {
		addr = endpoint[:i]
		rest := endpoint[i+1:]
		parts := strings.SplitN(rest, ",", 2)
		if d, err := strconv.Atoi(strings.TrimSpace(parts[0])); err == nil {
			db = d
		}
		if len(parts) > 1 {
			password = strings.TrimSpace(parts[1])
		}
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		DB:       db,
		Password: password,
	})

	if err := client.Ping(context.Background()).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return client, nil
}

// ── in-memory implementation (default) ──────────────────────────────────────

type memoryDeviceAuthStore struct {
	mu sync.RWMutex
	m  map[any]any
}

func (s *memoryDeviceAuthStore) Load(key any) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.m[key]
	return value, ok
}

func (s *memoryDeviceAuthStore) Store(key, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[any]any)
	}
	s.m[key] = value
}

func (s *memoryDeviceAuthStore) Delete(key any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

func (s *memoryDeviceAuthStore) LoadAndDelete(key any) (any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.m[key]
	if ok {
		delete(s.m, key)
	}
	return value, ok
}

func (s *memoryDeviceAuthStore) CompareAndSwapStatus(key any, applicationId string, clientId string, oldStatus string, newStatus string) (DeviceAuthCache, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.m[key]
	if !ok {
		return DeviceAuthCache{}, false
	}
	cache, ok := value.(DeviceAuthCache)
	if !ok || cache.ApplicationId != applicationId || cache.ClientId != clientId || cache.Status != oldStatus {
		return DeviceAuthCache{}, false
	}

	cache.Status = newStatus
	s.m[key] = cache
	return cache, true
}

func (s *memoryDeviceAuthStore) Range(f func(key, value any) bool) {
	s.mu.RLock()
	entries := make([]struct {
		key   any
		value any
	}, 0, len(s.m))
	for key, value := range s.m {
		entries = append(entries, struct {
			key   any
			value any
		}{key: key, value: value})
	}
	s.mu.RUnlock()

	for _, entry := range entries {
		if !f(entry.key, entry.value) {
			return
		}
	}
}

// ── Redis implementation ─────────────────────────────────────────────────────

type redisDeviceAuthStore struct {
	client *redis.Client
}

func (s *redisDeviceAuthStore) redisKey(key any) (string, bool) {
	k, ok := key.(string)
	return deviceAuthRedisPrefix + k, ok
}

func (s *redisDeviceAuthStore) Load(key any) (any, bool) {
	rk, ok := s.redisKey(key)
	if !ok {
		return nil, false
	}

	data, err := s.client.Get(context.Background(), rk).Bytes()
	if err != nil {
		return nil, false
	}

	var cache DeviceAuthCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, false
	}
	return cache, true
}

func (s *redisDeviceAuthStore) Store(key, value any) {
	rk, ok := s.redisKey(key)
	if !ok {
		return
	}

	cache, ok := value.(DeviceAuthCache)
	if !ok {
		return
	}

	data, err := json.Marshal(cache)
	if err != nil {
		logs.Warn("device_auth_store: failed to marshal DeviceAuthCache: %v", err)
		return
	}

	ttl := cache.ExpiresIn
	if ttl <= 0 {
		ttl = DeviceAuthExpiresIn
	}

	if err := s.client.Set(context.Background(), rk, data, time.Duration(ttl)*time.Second).Err(); err != nil {
		logs.Warn("device_auth_store: Redis SET failed: %v", err)
	}
}

func (s *redisDeviceAuthStore) Delete(key any) {
	rk, ok := s.redisKey(key)
	if !ok {
		return
	}

	if err := s.client.Del(context.Background(), rk).Err(); err != nil {
		logs.Warn("device_auth_store: Redis DEL failed: %v", err)
	}
}

func (s *redisDeviceAuthStore) LoadAndDelete(key any) (any, bool) {
	rk, ok := s.redisKey(key)
	if !ok {
		return nil, false
	}

	// GetDel is atomic and available since Redis 6.2. For older Redis the worst case is a
	// small window between GET and DEL where a concurrent request sees the same entry; that
	// is acceptable given the short device-auth TTL.
	data, err := s.client.GetDel(context.Background(), rk).Bytes()
	if err != nil {
		return nil, false
	}

	var cache DeviceAuthCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, false
	}
	return cache, true
}

var compareAndSwapDeviceAuthStatusScript = redis.NewScript(`
local current = redis.call("GET", KEYS[1])
if not current then
  return ""
end

local decoded = cjson.decode(current)
if decoded.ApplicationId ~= ARGV[1] or decoded.ClientId ~= ARGV[2] or decoded.Status ~= ARGV[3] then
  return ""
end

decoded.Status = ARGV[4]
local updated = cjson.encode(decoded)
local ttl = redis.call("PTTL", KEYS[1])
if ttl > 0 then
  redis.call("SET", KEYS[1], updated, "PX", ttl)
else
  redis.call("SET", KEYS[1], updated)
end
return updated
`)

// CompareAndSwapStatus is the cross-replica replay boundary for device-code
// token issuance. The application and client bindings are checked in the same
// Redis script as the status transition, and the original expiry is preserved.
func (s *redisDeviceAuthStore) CompareAndSwapStatus(key any, applicationId string, clientId string, oldStatus string, newStatus string) (DeviceAuthCache, bool) {
	rk, ok := s.redisKey(key)
	if !ok {
		return DeviceAuthCache{}, false
	}

	result, err := compareAndSwapDeviceAuthStatusScript.Run(
		context.Background(),
		s.client,
		[]string{rk},
		applicationId,
		clientId,
		oldStatus,
		newStatus,
	).Result()
	data, resultIsString := result.(string)
	if err != nil || !resultIsString || data == "" {
		if err != nil && err != redis.Nil {
			logs.Warn("device_auth_store: atomic status transition failed: %v", err)
		}
		return DeviceAuthCache{}, false
	}

	var cache DeviceAuthCache
	if err = json.Unmarshal([]byte(data), &cache); err != nil {
		logs.Warn("device_auth_store: failed to decode atomic status transition: %v", err)
		return DeviceAuthCache{}, false
	}
	return cache, true
}

// Range is a no-op for the Redis backend: entries expire automatically via TTL,
// so the periodic sweep in InitCleanupDeviceAuthMap is not needed.
func (s *redisDeviceAuthStore) Range(_ func(key, value any) bool) {}
