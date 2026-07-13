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

import "testing"

func TestMaskTokenForResponseRemovesCredentialsWithoutMutatingSource(t *testing.T) {
	token := &Token{
		Owner:                 "admin",
		Name:                  "token-id",
		Code:                  "authorization-code",
		AccessToken:           "access-token",
		RefreshToken:          "refresh-token",
		AccessTokenHash:       "access-hash",
		RefreshTokenHash:      "refresh-hash",
		RefreshTokenFamily:    "family-id",
		AuthenticationMethods: []string{"pwd", "otp"},
	}

	masked := MaskTokenForResponse(token)
	if masked == token {
		t.Fatal("MaskTokenForResponse returned the source pointer")
	}
	if masked.Code != "" || masked.AccessToken != "" || masked.RefreshToken != "" ||
		masked.AccessTokenHash != "" || masked.RefreshTokenHash != "" || masked.RefreshTokenFamily != "" {
		t.Fatalf("masked token still contains credential material: %#v", masked)
	}
	if masked.Owner != token.Owner || masked.Name != token.Name || len(masked.AuthenticationMethods) != 2 {
		t.Fatalf("masked token lost management metadata: %#v", masked)
	}

	masked.AuthenticationMethods[0] = "changed"
	if token.AccessToken != "access-token" || token.AuthenticationMethods[0] != "pwd" {
		t.Fatal("masking mutated or aliased the persisted token")
	}
}

func TestUpdateTokenCanOnlyShortenExpiration(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	persisted := &Token{
		Owner:              "admin",
		Name:               "managed-token",
		Organization:       "tenant",
		Code:               "authorization-code",
		AccessToken:        "access-token",
		RefreshToken:       "refresh-token",
		ExpiresIn:          3600,
		Scope:              "openid",
		TokenType:          "Bearer",
		RefreshTokenFamily: "family",
	}
	if _, err := AddToken(persisted); err != nil {
		t.Fatal(err)
	}

	requested := &Token{
		Organization: "attacker-controlled",
		Code:         "replacement-code",
		AccessToken:  "replacement-access-token",
		RefreshToken: "replacement-refresh-token",
		ExpiresIn:    0,
		Scope:        "admin",
	}
	updated, err := UpdateToken(persisted.GetId(), requested, true)
	if err != nil || !updated {
		t.Fatalf("revoke token = (%v, %v)", updated, err)
	}

	got, err := GetToken(persisted.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresIn != 0 || got.Code != persisted.Code || got.AccessToken != persisted.AccessToken ||
		got.RefreshToken != persisted.RefreshToken || got.Scope != persisted.Scope {
		t.Fatalf("revocation rewrote immutable token material: %#v", got)
	}

	if updated, err = UpdateToken(persisted.GetId(), &Token{ExpiresIn: 1}, true); err == nil || updated {
		t.Fatalf("expired token was extended: (%v, %v)", updated, err)
	}
}
