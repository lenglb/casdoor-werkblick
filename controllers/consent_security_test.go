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
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestConsentOAuthRequestMatchesBoundTransaction(t *testing.T) {
	expected := object.AuthorizationRequest{
		ClientId:      "client",
		ResponseType:  "code",
		ResponseMode:  "form_post",
		RedirectUri:   "https://client.example.test/callback",
		Scope:         "openid profile",
		State:         "caller+state",
		Nonce:         "nonce",
		CodeChallenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
		Resource:      "https://api.example.test",
	}
	request := consentOAuthRequest{
		ClientId:     expected.ClientId,
		ResponseType: expected.ResponseType,
		ResponseMode: expected.ResponseMode,
		RedirectUri:  expected.RedirectUri,
		Scope:        expected.Scope,
		State:        expected.State,
		Nonce:        expected.Nonce,
		Challenge:    expected.CodeChallenge,
		Resource:     expected.Resource,
	}
	if !request.matchesAuthorizationRequest(expected) {
		t.Fatal("matching consent request was rejected")
	}

	request.RedirectUri = "https://attacker.example.test/callback"
	if request.matchesAuthorizationRequest(expected) {
		t.Fatal("consent request accepted an unbound redirect URI")
	}
}

func TestBuildOAuthErrorCallbackUrl(t *testing.T) {
	redirect, err := buildOAuthErrorCallbackUrl(
		"https://client.example.test/callback?existing=1",
		"caller+state",
		"access_denied",
		"User denied consent",
	)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("existing") != "1" ||
		parsed.Query().Get("error") != "access_denied" ||
		parsed.Query().Get("error_description") != "User denied consent" ||
		parsed.Query().Get("state") != "caller+state" {
		t.Fatalf("unexpected OAuth error callback: %s", redirect)
	}
}

func TestBuildOAuthErrorCallbackUrlRejectsActiveContentSchemes(t *testing.T) {
	for _, redirect := range []string{
		"javascript:alert(document.domain)",
		"data:text/html,attack",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"/relative/callback",
	} {
		if result, err := buildOAuthErrorCallbackUrl(redirect, "state", "access_denied", "denied"); err == nil {
			t.Fatalf("unsafe redirect %q produced %q", redirect, result)
		}
	}
}
