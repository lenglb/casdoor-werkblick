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
	"net/url"
	"strings"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestBuildOAuthCallbackUrlDoesNotAllowStateParameterInjection(t *testing.T) {
	redirectUrl, err := buildOAuthCallbackUrl(
		"https://client.example.test/callback?existing=1#fragment",
		"issued-code",
		"state-value&code=attacker-code",
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirectUrl)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("code") != "issued-code" {
		t.Fatalf("code = %q", parsed.Query().Get("code"))
	}
	if parsed.Query().Get("state") != "state-value&code=attacker-code" {
		t.Fatalf("state = %q", parsed.Query().Get("state"))
	}
	if values := parsed.Query()["code"]; len(values) != 1 {
		t.Fatalf("code parameter count = %d, want 1", len(values))
	}
	if parsed.Fragment != "fragment" || parsed.Query().Get("existing") != "1" {
		t.Fatalf("callback components were lost: %s", redirectUrl)
	}
}

func TestBuildMfaConsentUrlPreservesBoundOAuthRequest(t *testing.T) {
	maxAge := int64(0)
	request := object.AuthorizationRequest{
		ClientId:        "client-id",
		ResponseType:    ResponseTypeCode,
		ResponseMode:    "form_post",
		RedirectUri:     "https://client.example.test/callback?existing=1",
		Scope:           "openid profile",
		State:           "state&code=attacker",
		Nonce:           "nonce",
		ChallengeMethod: "S256",
		CodeChallenge:   strings.Repeat("a", 43),
		Resource:        "https://api.example.test",
		Prompt:          "consent",
		MaxAge:          &maxAge,
	}
	consentUrl := buildMfaConsentUrl(&object.Application{Name: "test app"}, request)
	parsed, err := url.Parse(consentUrl)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/consent/test app" {
		t.Fatalf("path = %q", parsed.Path)
	}
	query := parsed.Query()
	checks := map[string]string{
		"client_id": request.ClientId, "response_type": request.ResponseType, "response_mode": request.ResponseMode,
		"redirect_uri": request.RedirectUri, "scope": request.Scope,
		"state": request.State, "nonce": request.Nonce,
		"code_challenge": request.CodeChallenge, "code_challenge_method": request.ChallengeMethod,
		"resource": request.Resource, "prompt": request.Prompt, "max_age": "0",
	}
	for key, want := range checks {
		if got := query.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestRequiredMfaMethodMustBeIndependentFromPrimaryAuthentication(t *testing.T) {
	tests := []struct {
		name    string
		context object.AuthenticationContext
		mfaType string
		wantErr bool
	}{
		{name: "password then TOTP", context: object.AuthenticationContext{Amr: []string{"pwd"}}, mfaType: object.TotpType},
		{name: "TOTP cannot repeat OTP", context: object.AuthenticationContext{Amr: []string{"otp"}}, mfaType: object.TotpType, wantErr: true},
		{name: "email cannot repeat email", context: object.AuthenticationContext{Amr: []string{"email"}}, mfaType: object.EmailType, wantErr: true},
		{name: "sms cannot repeat sms", context: object.AuthenticationContext{Amr: []string{"sms"}}, mfaType: object.SmsType, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ensureIndependentMfaMethod(tt.context, tt.mfaType)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ensureIndependentMfaMethod() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHardenedMfaSetupSupportsTotpOnly(t *testing.T) {
	for _, mfaType := range []string{object.SmsType, object.EmailType, object.RadiusType, object.PushType, ""} {
		if isSupportedMfaSetupType(mfaType) {
			t.Fatalf("unsafe MFA setup type %q was enabled", mfaType)
		}
	}
	if !isSupportedMfaSetupType(object.TotpType) {
		t.Fatal("TOTP setup was unexpectedly disabled")
	}
}
