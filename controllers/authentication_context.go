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
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

const pendingAuthenticationLifetime = 10 * time.Minute

// consumedAuthenticationTransactions closes the read/delete race for concurrent
// continuations handled by the same Casdoor process. Deleting the session value
// remains the cross-request source of truth; clustered deployments need an
// atomic shared session backend to extend this guarantee across replicas.
var consumedAuthenticationTransactions sync.Map

func (c *ApiController) getQueryValue(names ...string) string {
	for _, name := range names {
		if value := c.Ctx.Input.Query(name); value != "" {
			return value
		}
	}
	return ""
}

func (c *ApiController) captureAuthorizationRequest() (object.AuthorizationRequest, error) {
	request := object.AuthorizationRequest{
		ClientId:        c.getQueryValue("clientId", "client_id"),
		ResponseType:    c.getQueryValue("responseType", "response_type"),
		ResponseMode:    c.getQueryValue("responseMode", "response_mode"),
		RedirectUri:     c.getQueryValue("redirectUri", "redirect_uri"),
		Scope:           c.getQueryValue("scope"),
		State:           c.getQueryValue("state"),
		Nonce:           c.getQueryValue("nonce"),
		ChallengeMethod: c.getQueryValue("code_challenge_method", "codeChallengeMethod"),
		CodeChallenge:   c.getQueryValue("code_challenge", "codeChallenge"),
		Resource:        c.getQueryValue("resource"),
		Prompt:          c.getQueryValue("prompt"),
	}

	if maxAgeValue := c.getQueryValue("maxAge", "max_age"); maxAgeValue != "" {
		maxAge, err := strconv.ParseInt(maxAgeValue, 10, 64)
		if err != nil {
			return object.AuthorizationRequest{}, fmt.Errorf("authorization request max_age must be an integer")
		}
		request.MaxAge = &maxAge
	}

	if err := request.Validate(); err != nil {
		return object.AuthorizationRequest{}, err
	}
	return request, nil
}

func newAuthenticationContext(user *object.User, methods []string, provider string) (object.AuthenticationContext, error) {
	if user == nil {
		return object.AuthenticationContext{}, fmt.Errorf("authenticated user must not be nil")
	}
	return object.PreserveAuthenticationContext(object.AuthenticationContext{
		Subject:  user.GetId(),
		AuthTime: time.Now().Unix(),
		Amr:      methods,
		Provider: provider,
	})
}

func appendAuthenticationMethod(authenticationContext object.AuthenticationContext, methods ...string) (object.AuthenticationContext, error) {
	authenticationContext.AuthTime = time.Now().Unix()
	authenticationContext.Amr = append(authenticationContext.Amr, methods...)
	return object.PreserveAuthenticationContext(authenticationContext)
}

func mfaAuthenticationMethod(mfaType string) (string, error) {
	switch mfaType {
	case object.TotpType:
		return "otp", nil
	case object.SmsType:
		return "sms", nil
	case object.EmailType:
		return "email", nil
	case object.RadiusType:
		return "radius", nil
	case object.PushType:
		return "push", nil
	default:
		return "", fmt.Errorf("unsupported MFA type %q", mfaType)
	}
}

func (c *ApiController) beginAuthentication(user *object.User, methods []string, provider string, responseType string, application *object.Application, userCode string) (object.AuthenticationContext, error) {
	// A successful primary authentication starts a new security boundary. Drop
	// every identity-bearing value from an older browser session before MFA or
	// consent can pause the new transaction, otherwise that old identity would
	// remain authorized while the new challenge is still incomplete.
	if err := c.resetAuthenticationSessionForNewTransaction(); err != nil {
		return object.AuthenticationContext{}, err
	}

	authenticationContext, err := newAuthenticationContext(user, methods, provider)
	if err != nil {
		return object.AuthenticationContext{}, err
	}
	if application == nil {
		return object.AuthenticationContext{}, fmt.Errorf("authenticated application must not be nil")
	}

	pending := newPendingAuthentication(authenticationContext, responseType, application, userCode, nil)
	if responseType == ResponseTypeCode {
		request, err := c.captureAuthorizationRequest()
		if err != nil {
			return object.AuthenticationContext{}, err
		}
		pending.Request = &request
	}
	if err = c.setPendingAuthentication(pending); err != nil {
		return object.AuthenticationContext{}, err
	}
	return authenticationContext, nil
}

func (c *ApiController) resetAuthenticationSessionForNewTransaction() error {
	if err := c.SessionRegenerateID(); err != nil {
		return fmt.Errorf("regenerate primary-authentication session: %w", err)
	}
	identityKeys := []string{
		"username",
		"paidUsername",
		"accessToken",
		"scope",
		"aud",
		"SessionData",
		"impersonateUser",
		"verificationCodeType",
		object.MfaSessionUserId,
		object.MfaSetupSessionUserId,
		object.MfaSetupTransaction,
		object.CurrentAuthenticationContextSessionKey,
		object.PendingAuthenticationSessionKey,
	}
	for _, key := range identityKeys {
		if err := c.DelSession(key); err != nil {
			return fmt.Errorf("clear previous authentication session value %q: %w", key, err)
		}
	}
	return nil
}

func newPendingAuthentication(authenticationContext object.AuthenticationContext, responseType string, application *object.Application, userCode string, request *object.AuthorizationRequest) object.PendingAuthentication {
	now := time.Now()
	return object.PendingAuthentication{
		Context:       authenticationContext,
		Request:       request,
		FlowType:      responseType,
		ApplicationId: application.GetId(),
		UserCode:      userCode,
		TransactionId: util.GenerateId(),
		CreatedAt:     now.Unix(),
		ExpiresAt:     now.Add(pendingAuthenticationLifetime).Unix(),
	}
}

func (c *ApiController) completeAuthentication(authenticationContext object.AuthenticationContext) error {
	if err := c.SessionRegenerateID(); err != nil {
		return fmt.Errorf("regenerate authenticated session: %w", err)
	}
	if err := c.setCurrentAuthenticationContext(authenticationContext); err != nil {
		return err
	}
	return nil
}

func (c *ApiController) setCurrentAuthenticationContext(authenticationContext object.AuthenticationContext) error {
	preserved, err := object.PreserveAuthenticationContext(authenticationContext)
	if err != nil {
		return err
	}
	return c.SetSession(object.CurrentAuthenticationContextSessionKey, util.StructToJson(preserved))
}

func (c *ApiController) getCurrentAuthenticationContext() (object.AuthenticationContext, error) {
	value := c.GetSession(object.CurrentAuthenticationContextSessionKey)
	if value == nil {
		return object.AuthenticationContext{}, fmt.Errorf("authentication context is missing")
	}
	serialized, ok := value.(string)
	if !ok || strings.TrimSpace(serialized) == "" {
		return object.AuthenticationContext{}, fmt.Errorf("authentication context session value is invalid")
	}

	var authenticationContext object.AuthenticationContext
	if err := util.JsonToStruct(serialized, &authenticationContext); err != nil {
		return object.AuthenticationContext{}, fmt.Errorf("decode authentication context: %w", err)
	}
	return object.PreserveAuthenticationContext(authenticationContext)
}

func (c *ApiController) clearCurrentAuthenticationContext() error {
	return c.DelSession(object.CurrentAuthenticationContextSessionKey)
}

func (c *ApiController) setPendingAuthentication(pending object.PendingAuthentication) error {
	preserved, err := pending.Preserve()
	if err != nil {
		return err
	}
	return c.SetSession(object.PendingAuthenticationSessionKey, util.StructToJson(preserved))
}

func (c *ApiController) getPendingAuthentication() (object.PendingAuthentication, error) {
	value := c.GetSession(object.PendingAuthenticationSessionKey)
	if value == nil {
		return object.PendingAuthentication{}, fmt.Errorf("pending authentication is missing")
	}
	serialized, ok := value.(string)
	if !ok || strings.TrimSpace(serialized) == "" {
		return object.PendingAuthentication{}, fmt.Errorf("pending authentication session value is invalid")
	}

	var pending object.PendingAuthentication
	if err := util.JsonToStruct(serialized, &pending); err != nil {
		return object.PendingAuthentication{}, fmt.Errorf("decode pending authentication: %w", err)
	}
	return pending.Preserve()
}

func (c *ApiController) clearPendingAuthentication() error {
	return c.DelSession(object.PendingAuthenticationSessionKey)
}

func (c *ApiController) consumePendingAuthentication(transactionId string, expiresAt int64) error {
	pending, err := c.getPendingAuthentication()
	if err != nil {
		return err
	}
	if pending.TransactionId != transactionId || pending.ExpiresAt != expiresAt {
		return fmt.Errorf("pending authentication transaction does not match")
	}

	if !claimPendingAuthenticationTransaction(transactionId, expiresAt, time.Now().Unix()) {
		return fmt.Errorf("pending authentication transaction has already been consumed")
	}

	if err = c.clearPendingAuthentication(); err != nil {
		consumedAuthenticationTransactions.Delete(transactionId)
		return fmt.Errorf("clear consumed authentication transaction: %w", err)
	}
	c.Ctx.Input.CruSession.SessionRelease(context.Background(), c.Ctx.ResponseWriter)
	return nil
}

func claimPendingAuthenticationTransaction(transactionId string, expiresAt int64, now int64) bool {
	consumedAuthenticationTransactions.Range(func(key, value any) bool {
		if expiry, ok := value.(int64); !ok || expiry < now {
			consumedAuthenticationTransactions.Delete(key)
		}
		return true
	})
	_, loaded := consumedAuthenticationTransactions.LoadOrStore(transactionId, expiresAt)
	return !loaded
}
