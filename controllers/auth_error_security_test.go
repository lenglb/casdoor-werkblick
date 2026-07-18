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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	beegocontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

type testSessionStore struct {
	mutex     sync.Mutex
	sessionId string
	values    map[interface{}]interface{}
}

func (store *testSessionStore) Set(_ context.Context, key, value interface{}) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.values == nil {
		store.values = map[interface{}]interface{}{}
	}
	store.values[key] = value
	return nil
}

func (store *testSessionStore) Get(_ context.Context, key interface{}) interface{} {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.values[key]
}

func (store *testSessionStore) Delete(_ context.Context, key interface{}) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	delete(store.values, key)
	return nil
}

func (store *testSessionStore) SessionID(context.Context) string {
	return store.sessionId
}

func (store *testSessionStore) SessionReleaseIfPresent(context.Context, http.ResponseWriter) {}

func (store *testSessionStore) SessionRelease(context.Context, http.ResponseWriter) {}

func (store *testSessionStore) Flush(context.Context) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.values = map[interface{}]interface{}{}
	return nil
}

func TestUnknownAuthenticationTypeMessageExcludesCredentials(t *testing.T) {
	authForm := &form.AuthForm{
		Type:         ResponseTypeCode,
		SigninMethod: "Password",
		Organization: "werkblick-demo",
		Application:  "schedule",
		Username:     "sensitive-user",
		Password:     "sensitive-password",
		Passcode:     "123456",
		RecoveryCode: "sensitive-recovery-code",
		ClientSecret: "sensitive-client-secret",
		Code:         "sensitive-authorization-code",
		CodeVerifier: "sensitive-code-verifier",
		SamlResponse: "sensitive-saml-response",
	}

	message := unknownAuthenticationTypeMessage("en", authForm)
	for _, secret := range []string{
		authForm.Username,
		authForm.Password,
		authForm.Passcode,
		authForm.RecoveryCode,
		authForm.ClientSecret,
		authForm.Code,
		authForm.CodeVerifier,
		authForm.SamlResponse,
	} {
		if strings.Contains(message, secret) {
			t.Fatalf("unknown authentication type message leaks a credential: %q", message)
		}
	}

	jsonStart := strings.IndexByte(message, '{')
	if jsonStart == -1 {
		t.Fatalf("unknown authentication type message has no diagnostic summary: %q", message)
	}
	var summary map[string]string
	if err := json.Unmarshal([]byte(message[jsonStart:]), &summary); err != nil {
		t.Fatalf("parse diagnostic summary: %v", err)
	}
	expected := map[string]string{
		"type":         authForm.Type,
		"signinMethod": authForm.SigninMethod,
		"organization": authForm.Organization,
		"application":  authForm.Application,
	}
	if len(summary) != len(expected) {
		t.Fatalf("diagnostic summary contains unexpected AuthForm fields: %#v", summary)
	}
	for key, value := range expected {
		if summary[key] != value {
			t.Fatalf("diagnostic summary field %q = %q, want %q", key, summary[key], value)
		}
	}
}

func TestMissingOrOldSessionMfaSubmissionGetsStableRedactedRestartMessage(t *testing.T) {
	forms := []*form.AuthForm{
		{Passcode: "123456", ClientSecret: "secret", CodeVerifier: "verifier"},
		{RecoveryCode: "recovery-secret", SamlResponse: "assertion"},
	}
	for _, authForm := range forms {
		if !isMfaContinuationSubmission(authForm) {
			t.Fatalf("MFA continuation was not detected: %#v", authForm)
		}
		for _, secret := range []string{authForm.Passcode, authForm.RecoveryCode, authForm.ClientSecret, authForm.CodeVerifier, authForm.SamlResponse} {
			if secret != "" && strings.Contains(mfaRestartLoginMessage, secret) {
				t.Fatalf("restart-login message leaks a credential: %q", mfaRestartLoginMessage)
			}
		}
	}

	for _, authForm := range []*form.AuthForm{
		nil,
		{},
		{Username: "alice", Password: "password"},
		{MfaType: "app"},
	} {
		if isMfaContinuationSubmission(authForm) {
			t.Fatalf("non-MFA login was classified as a continuation: %#v", authForm)
		}
	}
}

func TestLoginWithOldSidReturnsStableRedactedMfaRestartMessage(t *testing.T) {
	authForm := &form.AuthForm{
		Type:         ResponseTypeCode,
		SigninMethod: "Password",
		Organization: "werkblick-demo",
		Application:  "schedule",
		MfaType:      "app",
		Passcode:     "654321",
		ClientSecret: "sensitive-client-secret",
		CodeVerifier: "sensitive-code-verifier",
	}
	body, err := json.Marshal(authForm)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	ctx := beegocontext.NewContext()
	ctx.Reset(recorder, request)
	ctx.Input.RequestBody = body
	ctx.Input.CruSession = &testSessionStore{sessionId: "old-sid"}

	controller := &ApiController{}
	controller.Init(ctx, "ApiController", "Login", controller)
	controller.Login()

	response, ok := controller.Data["json"].(*Response)
	if !ok {
		t.Fatalf("response = %#v, want *Response", controller.Data["json"])
	}
	if response.Status != "error" || response.Msg != mfaRestartLoginMessage {
		t.Fatalf("response = %#v, want stable MFA restart error", response)
	}
	for _, secret := range []string{authForm.Passcode, authForm.ClientSecret, authForm.CodeVerifier} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("old-SID response leaks a credential: %s", recorder.Body.String())
		}
	}
}

func TestDirectMfaOAuthCodeTransactionCanBeConsumedExactlyOnce(t *testing.T) {
	now := time.Now()
	pending := object.PendingAuthentication{
		Context: object.AuthenticationContext{
			Subject:  "werkblick-demo/alice",
			AuthTime: now.Unix(),
			Amr:      []string{"pwd", "otp"},
		},
		Request: &object.AuthorizationRequest{
			ClientId:     "schedule-client",
			ResponseType: ResponseTypeCode,
			RedirectUri:  "https://schedule.demo.werkblick.tech/api/auth/callback",
		},
		FlowType:      ResponseTypeCode,
		ApplicationId: "admin/schedule",
		TransactionId: t.Name(),
		CreatedAt:     now.Unix(),
		ExpiresAt:     now.Add(time.Minute).Unix(),
	}
	preserved, err := pending.Preserve()
	if err != nil {
		t.Fatal(err)
	}
	defer consumedAuthenticationTransactions.Delete(preserved.TransactionId)

	store := &testSessionStore{sessionId: "shared-sid", values: map[interface{}]interface{}{
		object.PendingAuthenticationSessionKey: util.StructToJson(preserved),
	}}
	newController := func() *ApiController {
		request := httptest.NewRequest(http.MethodPost, "/api/login", nil)
		ctx := beegocontext.NewContext()
		ctx.Reset(httptest.NewRecorder(), request)
		ctx.Input.CruSession = store
		controller := &ApiController{}
		controller.Init(ctx, "ApiController", "Login", controller)
		return controller
	}

	const attempts = 16
	var successes atomic.Int32
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer waitGroup.Done()
			controller := newController()
			if consumeErr := controller.consumePendingAuthentication(preserved.TransactionId, preserved.ExpiresAt); consumeErr == nil {
				successes.Add(1)
			}
		}()
	}
	waitGroup.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("successful direct MFA OAuth transaction consumptions = %d, want 1", got)
	}
	if value := store.Get(context.Background(), object.PendingAuthenticationSessionKey); value != nil {
		t.Fatalf("consumed pending authentication remains in session: %#v", value)
	}
}
