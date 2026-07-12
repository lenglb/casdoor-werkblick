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

import "time"

type DeviceAuthTokenClaimResult string

const (
	DeviceAuthTokenClaimed            DeviceAuthTokenClaimResult = "claimed"
	DeviceAuthTokenNotFound           DeviceAuthTokenClaimResult = "not_found"
	DeviceAuthTokenExpired            DeviceAuthTokenClaimResult = "expired"
	DeviceAuthTokenPending            DeviceAuthTokenClaimResult = "pending"
	DeviceAuthTokenDenied             DeviceAuthTokenClaimResult = "denied"
	DeviceAuthTokenIssuanceInProgress DeviceAuthTokenClaimResult = "token_issuing"
	DeviceAuthTokenAlreadyIssued      DeviceAuthTokenClaimResult = "token_issued"
	DeviceAuthTokenBindingMismatch    DeviceAuthTokenClaimResult = "binding_mismatch"
	DeviceAuthTokenInvalid            DeviceAuthTokenClaimResult = "invalid"
)

// ClaimDeviceAuthTokenIssuance moves an approved device authorization into an
// exclusive token-minting state. The status transition and the original
// application/client binding check happen atomically in the configured store.
func ClaimDeviceAuthTokenIssuance(deviceCode string, applicationId string, clientId string, now time.Time) (DeviceAuthCache, DeviceAuthTokenClaimResult) {
	return claimDeviceAuthTokenIssuance(DeviceAuthMap, deviceCode, applicationId, clientId, now)
}

func claimDeviceAuthTokenIssuance(store deviceAuthStore, deviceCode string, applicationId string, clientId string, now time.Time) (DeviceAuthCache, DeviceAuthTokenClaimResult) {
	if store == nil || deviceCode == "" || applicationId == "" || clientId == "" {
		return DeviceAuthCache{}, DeviceAuthTokenInvalid
	}

	// A failed CAS means another request changed the status after our read. One
	// reload is normally enough to classify that winning transition; a small
	// bounded loop also tolerates a concurrent rollback after a minting error.
	for attempt := 0; attempt < 3; attempt++ {
		value, ok := store.Load(deviceCode)
		if !ok {
			return DeviceAuthCache{}, DeviceAuthTokenNotFound
		}
		cache, ok := value.(DeviceAuthCache)
		if !ok {
			return DeviceAuthCache{}, DeviceAuthTokenInvalid
		}

		expiresIn := cache.ExpiresIn
		if expiresIn <= 0 {
			expiresIn = DeviceAuthExpiresIn
		}
		if cache.RequestAt.IsZero() || !now.Before(cache.RequestAt.Add(time.Duration(expiresIn)*time.Second)) {
			return DeviceAuthCache{}, DeviceAuthTokenExpired
		}
		if cache.ApplicationId != applicationId || cache.ClientId != clientId {
			return DeviceAuthCache{}, DeviceAuthTokenBindingMismatch
		}

		switch cache.Status {
		case DeviceAuthStatusPending:
			return DeviceAuthCache{}, DeviceAuthTokenPending
		case DeviceAuthStatusDenied:
			return DeviceAuthCache{}, DeviceAuthTokenDenied
		case DeviceAuthStatusTokenIssuing:
			return DeviceAuthCache{}, DeviceAuthTokenIssuanceInProgress
		case DeviceAuthStatusTokenIssued:
			return DeviceAuthCache{}, DeviceAuthTokenAlreadyIssued
		case DeviceAuthStatusApproved:
			if !cache.UserSignIn || cache.UserName == "" {
				return DeviceAuthCache{}, DeviceAuthTokenInvalid
			}
			claimed, swapped := store.CompareAndSwapStatus(
				deviceCode,
				applicationId,
				clientId,
				DeviceAuthStatusApproved,
				DeviceAuthStatusTokenIssuing,
			)
			if swapped {
				claimed.AuthenticationContext = claimed.AuthenticationContext.Clone()
				return claimed, DeviceAuthTokenClaimed
			}
		default:
			return DeviceAuthCache{}, DeviceAuthTokenInvalid
		}
	}

	return DeviceAuthCache{}, DeviceAuthTokenIssuanceInProgress
}

func CompleteDeviceAuthTokenIssuance(deviceCode string, applicationId string, clientId string) bool {
	return completeDeviceAuthTokenIssuance(DeviceAuthMap, deviceCode, applicationId, clientId)
}

func completeDeviceAuthTokenIssuance(store deviceAuthStore, deviceCode string, applicationId string, clientId string) bool {
	_, ok := store.CompareAndSwapStatus(
		deviceCode,
		applicationId,
		clientId,
		DeviceAuthStatusTokenIssuing,
		DeviceAuthStatusTokenIssued,
	)
	return ok
}

func RollbackDeviceAuthTokenIssuance(deviceCode string, applicationId string, clientId string) bool {
	return rollbackDeviceAuthTokenIssuance(DeviceAuthMap, deviceCode, applicationId, clientId)
}

func rollbackDeviceAuthTokenIssuance(store deviceAuthStore, deviceCode string, applicationId string, clientId string) bool {
	_, ok := store.CompareAndSwapStatus(
		deviceCode,
		applicationId,
		clientId,
		DeviceAuthStatusTokenIssuing,
		DeviceAuthStatusApproved,
	)
	return ok
}
