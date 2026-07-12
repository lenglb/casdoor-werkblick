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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/go-webauthn/webauthn/webauthn"
)

func validWebAuthnAuthorizationRequest() object.AuthorizationRequest {
	maxAge := int64(300)
	return object.AuthorizationRequest{
		ClientId:        "client-id",
		ResponseType:    ResponseTypeCode,
		RedirectUri:     "https://client.example.test/callback",
		Scope:           "openid profile",
		State:           "state-value",
		Nonce:           "nonce-value",
		ChallengeMethod: "S256",
		CodeChallenge:   strings.Repeat("a", 43),
		Resource:        "https://api.example.test",
		Prompt:          "login",
		MaxAge:          &maxAge,
	}
}

func validWebAuthnSessionData() webauthn.SessionData {
	return webauthn.SessionData{
		Challenge: "webauthn-challenge",
		Expires:   time.Now().Add(5 * time.Minute),
	}
}

func TestNewWebAuthnSigninSessionBindsAuthorizationRequestWithoutAliasing(t *testing.T) {
	request := validWebAuthnAuthorizationRequest()
	session, err := newWebAuthnSigninSession(validWebAuthnSessionData(), ResponseTypeCode, &request)
	if err != nil {
		t.Fatalf("newWebAuthnSigninSession() error = %v", err)
	}
	if session.Request == nil || !session.Request.Equal(request) {
		t.Fatal("newWebAuthnSigninSession() did not bind the authorization request")
	}

	*request.MaxAge = 0
	if session.Request.MaxAge == nil || *session.Request.MaxAge != 300 {
		t.Fatal("bound authorization request aliases caller-owned max_age")
	}

	var decoded webAuthnSigninSession
	if err = util.JsonToStruct(util.StructToJson(session), &decoded); err != nil {
		t.Fatalf("decode serialized WebAuthn session: %v", err)
	}
	if err = decoded.validate(time.Now()); err != nil {
		t.Fatalf("serialized WebAuthn session is invalid: %v", err)
	}
	if decoded.Request == nil || !decoded.Request.Equal(*session.Request) {
		t.Fatal("serialized WebAuthn session lost its authorization request")
	}
}

func TestWebAuthnSigninSessionValidationRequiresBoundCodeRequest(t *testing.T) {
	_, err := newWebAuthnSigninSession(validWebAuthnSessionData(), ResponseTypeCode, nil)
	if err == nil || !strings.Contains(err.Error(), "requires an OAuth authorization request") {
		t.Fatalf("newWebAuthnSigninSession() error = %v, want missing request error", err)
	}

	request := validWebAuthnAuthorizationRequest()
	_, err = newWebAuthnSigninSession(validWebAuthnSessionData(), ResponseTypeLogin, &request)
	if err == nil || !strings.Contains(err.Error(), "non-code") {
		t.Fatalf("newWebAuthnSigninSession() error = %v, want non-code request error", err)
	}

	expired := validWebAuthnSessionData()
	expired.Expires = time.Now().Add(-time.Second)
	_, err = newWebAuthnSigninSession(expired, ResponseTypeLogin, nil)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("newWebAuthnSigninSession() error = %v, want expiry error", err)
	}
}

func TestWebAuthnSigninSessionMatchesExactContinuation(t *testing.T) {
	request := validWebAuthnAuthorizationRequest()
	session, err := newWebAuthnSigninSession(validWebAuthnSessionData(), ResponseTypeCode, &request)
	if err != nil {
		t.Fatalf("newWebAuthnSigninSession() error = %v", err)
	}

	if err = session.matchesContinuation(ResponseTypeCode, &request); err != nil {
		t.Fatalf("matchesContinuation() exact request error = %v", err)
	}

	tests := []struct {
		name         string
		responseType string
		mutate       func(*object.AuthorizationRequest)
	}{
		{name: "response type", responseType: ResponseTypeLogin},
		{name: "client", responseType: ResponseTypeCode, mutate: func(candidate *object.AuthorizationRequest) { candidate.ClientId = "other-client" }},
		{name: "redirect", responseType: ResponseTypeCode, mutate: func(candidate *object.AuthorizationRequest) {
			candidate.RedirectUri = "https://attacker.example.test/callback"
		}},
		{name: "state", responseType: ResponseTypeCode, mutate: func(candidate *object.AuthorizationRequest) { candidate.State = "other-state" }},
		{name: "nonce", responseType: ResponseTypeCode, mutate: func(candidate *object.AuthorizationRequest) { candidate.Nonce = "other-nonce" }},
		{name: "PKCE", responseType: ResponseTypeCode, mutate: func(candidate *object.AuthorizationRequest) { candidate.CodeChallenge = strings.Repeat("b", 43) }},
		{name: "scope", responseType: ResponseTypeCode, mutate: func(candidate *object.AuthorizationRequest) { candidate.Scope = "openid admin" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := request.Clone()
			if tt.mutate != nil {
				tt.mutate(&candidate)
			}
			if err := session.matchesContinuation(tt.responseType, &candidate); err == nil {
				t.Fatal("matchesContinuation() accepted a changed authorization request")
			}
		})
	}
}

func TestClaimWebAuthnSigninTransactionOnce(t *testing.T) {
	transactionId := util.GenerateId()
	expiresAt := time.Now().Add(time.Minute).Unix()
	consumedWebAuthnSigninTransactions.Delete(transactionId)
	t.Cleanup(func() { consumedWebAuthnSigninTransactions.Delete(transactionId) })

	const workers = 32
	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer waitGroup.Done()
			if claimWebAuthnSigninTransaction(transactionId, expiresAt, time.Now().Unix()) {
				successes.Add(1)
			}
		}()
	}
	waitGroup.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("claimWebAuthnSigninTransaction() successes = %d, want 1", got)
	}
	if claimWebAuthnSigninTransaction(transactionId, expiresAt, time.Now().Unix()) {
		t.Fatal("claimWebAuthnSigninTransaction() accepted a replay")
	}
}
