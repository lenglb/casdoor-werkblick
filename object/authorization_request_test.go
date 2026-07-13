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
	"reflect"
	"strings"
	"testing"
	"time"
)

func validAuthorizationRequest() AuthorizationRequest {
	maxAge := int64(300)
	return AuthorizationRequest{
		ClientId:        "client-id",
		ResponseType:    "code",
		ResponseMode:    "form_post",
		RedirectUri:     "https://client.example.com/callback",
		Scope:           "openid profile",
		State:           "state",
		Nonce:           "nonce",
		ChallengeMethod: "S256",
		CodeChallenge:   strings.Repeat("a", 43),
		Resource:        "https://api.example.com",
		MaxAge:          &maxAge,
	}
}

func TestAuthorizationRequestValidate(t *testing.T) {
	valid := validAuthorizationRequest()
	tests := []struct {
		name    string
		mutate  func(*AuthorizationRequest)
		wantErr string
	}{
		{name: "valid"},
		{name: "valid without PKCE", mutate: func(request *AuthorizationRequest) { request.ChallengeMethod, request.CodeChallenge = "", "" }},
		{name: "valid query response", mutate: func(request *AuthorizationRequest) { request.ResponseMode = "query" }},
		{name: "missing client", mutate: func(request *AuthorizationRequest) { request.ClientId = "" }, wantErr: "client_id"},
		{name: "unsupported response", mutate: func(request *AuthorizationRequest) { request.ResponseType = "token" }, wantErr: "response_type"},
		{name: "unsupported response mode", mutate: func(request *AuthorizationRequest) { request.ResponseMode = "fragment" }, wantErr: "response_mode"},
		{name: "missing redirect", mutate: func(request *AuthorizationRequest) { request.RedirectUri = "" }, wantErr: "redirect_uri"},
		{name: "plain PKCE", mutate: func(request *AuthorizationRequest) { request.ChallengeMethod = "plain" }, wantErr: "must be S256"},
		{name: "challenge without method", mutate: func(request *AuthorizationRequest) { request.ChallengeMethod = "" }, wantErr: "provided together"},
		{name: "method without challenge", mutate: func(request *AuthorizationRequest) { request.CodeChallenge = "" }, wantErr: "provided together"},
		{name: "short challenge", mutate: func(request *AuthorizationRequest) { request.CodeChallenge = strings.Repeat("a", 42) }, wantErr: "between 43 and 128"},
		{name: "long challenge", mutate: func(request *AuthorizationRequest) { request.CodeChallenge = strings.Repeat("a", 129) }, wantErr: "between 43 and 128"},
		{name: "invalid challenge character", mutate: func(request *AuthorizationRequest) { request.CodeChallenge = strings.Repeat("a", 42) + "=" }, wantErr: "invalid character"},
		{name: "negative max age", mutate: func(request *AuthorizationRequest) { negative := int64(-1); request.MaxAge = &negative }, wantErr: "must not be negative"},
		{name: "unknown prompt", mutate: func(request *AuthorizationRequest) { request.Prompt = "create" }, wantErr: "not supported"},
		{name: "none with login", mutate: func(request *AuthorizationRequest) { request.Prompt = "none login" }, wantErr: "cannot be combined"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := valid
			if tt.mutate != nil {
				tt.mutate(&request)
			}
			err := request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthorizationRequestExceedsMaxAgeIgnoresSatisfiedPromptLogin(t *testing.T) {
	now := int64(1_752_000_000)
	request := AuthorizationRequest{Prompt: "login", MaxAge: int64Pointer(300)}
	context := AuthenticationContext{Subject: "werkblick/bernhard", AuthTime: now - 60, Amr: []string{"pwd"}}

	if request.ExceedsMaxAge(context, now) {
		t.Fatal("ExceedsMaxAge() treated an already-satisfied prompt=login as stale")
	}
	if !request.RequiresFreshAuthentication(context, now) {
		t.Fatal("RequiresFreshAuthentication() ignored prompt=login")
	}
}

func TestAuthorizationRequestFreshAuthenticationMatrix(t *testing.T) {
	now := int64(1_752_000_000)
	context := AuthenticationContext{
		Subject:  "werkblick/bernhard",
		AuthTime: now - 60,
		Amr:      []string{"pwd", "otp"},
	}

	tests := []struct {
		name    string
		prompt  string
		maxAge  *int64
		context AuthenticationContext
		want    bool
	}{
		{name: "no constraint", context: context, want: false},
		{name: "prompt login", prompt: "login", context: context, want: true},
		{name: "select account", prompt: "select_account", context: context, want: true},
		{name: "max age fresh", maxAge: int64Pointer(60), context: context, want: false},
		{name: "max age stale", maxAge: int64Pointer(59), context: context, want: true},
		{name: "max age zero", maxAge: int64Pointer(0), context: context, want: true},
		{name: "missing auth time", maxAge: int64Pointer(300), context: AuthenticationContext{Subject: context.Subject, Amr: context.Amr}, want: true},
		{name: "future auth time", maxAge: int64Pointer(300), context: AuthenticationContext{Subject: context.Subject, AuthTime: now + 1, Amr: context.Amr}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := AuthorizationRequest{Prompt: tt.prompt, MaxAge: tt.maxAge}
			if got := request.RequiresFreshAuthentication(tt.context, now); got != tt.want {
				t.Fatalf("RequiresFreshAuthentication() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthorizationRequestEqual(t *testing.T) {
	request := validAuthorizationRequest()
	clone := request.Clone()
	if !request.Equal(clone) {
		t.Fatal("Equal() rejected an exact clone")
	}
	*clone.MaxAge = 0
	if request.Equal(clone) {
		t.Fatal("Equal() accepted a different max_age")
	}
	clone = request.Clone()
	clone.Nonce = "different"
	if request.Equal(clone) {
		t.Fatal("Equal() accepted a different nonce")
	}
	clone = request.Clone()
	clone.ResponseMode = "query"
	if request.Equal(clone) {
		t.Fatal("Equal() accepted a different response_mode")
	}
}

func TestPendingAuthenticationPreserveDoesNotAlias(t *testing.T) {
	pending := PendingAuthentication{
		Context: AuthenticationContext{
			Subject:  " werkblick/bernhard ",
			AuthTime: 1_752_000_000,
			Amr:      []string{" pwd ", "otp", "pwd"},
		},
		FlowType:      "code",
		ApplicationId: "admin/app",
		TransactionId: "transaction-id",
		CreatedAt:     time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:     time.Now().Add(time.Minute).Unix(),
	}
	request := validAuthorizationRequest()
	pending.Request = &request

	got, err := pending.Preserve()
	if err != nil {
		t.Fatalf("Preserve() error = %v", err)
	}
	if !reflect.DeepEqual(got.Context.Amr, []string{"pwd", "otp"}) {
		t.Fatalf("Preserve() AMR = %#v", got.Context.Amr)
	}
	*got.Request.MaxAge = 0
	got.Context.Amr[0] = "changed"
	if *pending.Request.MaxAge != 300 || pending.Context.Amr[0] != " pwd " {
		t.Fatal("Preserve() returned values that alias pending session state")
	}
}

func TestPendingAuthenticationAllowsNonOAuthFlow(t *testing.T) {
	pending := PendingAuthentication{
		Context: AuthenticationContext{
			Subject:  "werkblick/bernhard",
			AuthTime: 1_752_000_000,
			Amr:      []string{"pwd"},
		},
		FlowType:      "login",
		ApplicationId: "admin/app",
		TransactionId: "transaction-id",
		CreatedAt:     time.Now().Add(-time.Minute).Unix(),
		ExpiresAt:     time.Now().Add(time.Minute).Unix(),
	}
	got, err := pending.Preserve()
	if err != nil {
		t.Fatalf("Preserve() error = %v", err)
	}
	if got.Request != nil {
		t.Fatalf("Preserve() request = %#v, want nil", got.Request)
	}
}

func int64Pointer(value int64) *int64 {
	return &value
}
