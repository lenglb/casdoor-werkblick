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
	"errors"
	"fmt"
	"time"

	"github.com/casdoor/casdoor/notification"
	"github.com/casdoor/casdoor/util"
)

type PushMfa struct {
	*MfaProps
	provider     *Provider
	challengeId  string
	challengeExp time.Time
}

var errPushMfaApprovalUnavailable = errors.New("push MFA is disabled until a signed, one-time approval callback is implemented")

func (mfa *PushMfa) Initiate(userId string, issuer string) (*MfaProps, error) {
	mfaProps := MfaProps{
		MfaType: mfa.MfaType,
	}
	return &mfaProps, nil
}

func (mfa *PushMfa) SetupVerify(passCode string) error {
	// Sending a notification is not proof that the user approved it. Fail closed
	// until the challenge has a signed, user/device-bound, expiring and one-shot
	// callback that can be verified here.
	return errPushMfaApprovalUnavailable
}

func (mfa *PushMfa) Enable(user *User) error {
	return errPushMfaApprovalUnavailable
}

func (mfa *PushMfa) Verify(passCode string) error {
	return errPushMfaApprovalUnavailable
}

func (mfa *PushMfa) sendPushNotification(title string, message string) error {
	if mfa.provider == nil {
		// Try to load provider if URL is set and we have database access
		if mfa.URL != "" && ormer != nil && ormer.Engine != nil {
			provider, err := GetProvider(mfa.URL)
			if err != nil {
				return fmt.Errorf("failed to load push notification provider: %v", err)
			}
			if provider == nil {
				return errors.New("push notification provider not found")
			}
			mfa.provider = provider
		} else {
			return errors.New("push notification provider is not configured")
		}
	}

	// Generate a unique challenge ID for this notification
	// Note: In a full implementation, this would be stored in a cache/database
	// to validate callbacks from the mobile app
	mfa.challengeId = util.GenerateUUID()
	mfa.challengeExp = time.Now().Add(5 * time.Minute) // Challenge expires in 5 minutes

	// Get the notification provider
	notifier, err := notification.GetNotificationProvider(
		mfa.provider.Type,
		mfa.provider.ClientId,
		mfa.provider.ClientSecret,
		mfa.provider.ClientId2,
		mfa.provider.ClientSecret2,
		mfa.provider.AppId,
		mfa.Secret, // receiver
		mfa.provider.Method,
		title,
		mfa.provider.Metadata,
		mfa.provider.RegionId,
	)
	if err != nil {
		return fmt.Errorf("failed to create notification provider: %v", err)
	}

	if notifier == nil {
		return errors.New("notification provider is not supported")
	}

	// Send the push notification
	// Note: The challengeId is kept server-side and not exposed in the message
	ctx := context.Background()
	err = notifier.Send(ctx, title, message)
	if err != nil {
		return fmt.Errorf("failed to send push notification: %v", err)
	}

	return nil
}

func NewPushMfaUtil(config *MfaProps) *PushMfa {
	if config == nil {
		config = &MfaProps{
			MfaType: PushType,
		}
	}

	pushMfa := &PushMfa{
		MfaProps: config,
	}

	// Load provider if URL is specified and ormer is initialized
	if config.URL != "" && ormer != nil && ormer.Engine != nil {
		provider, err := GetProvider(config.URL)
		if err == nil && provider != nil {
			pushMfa.provider = provider
		}
	}

	return pushMfa
}
