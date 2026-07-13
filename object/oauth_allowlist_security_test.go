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

func TestGrantTypesRequireExplicitAllowlistEntry(t *testing.T) {
	tests := []struct {
		name       string
		grantType  string
		grantTypes []string
		want       bool
	}{
		{
			name:       "admin m2m cannot use authorization code",
			grantType:  "authorization_code",
			grantTypes: []string{"client_credentials"},
			want:       false,
		},
		{
			name:       "browser explicitly allows authorization code",
			grantType:  "authorization_code",
			grantTypes: []string{"authorization_code"},
			want:       true,
		},
		{
			name:       "empty allowlist rejects authorization code",
			grantType:  "authorization_code",
			grantTypes: nil,
			want:       false,
		},
		{
			name:       "other grant remains explicitly allowed",
			grantType:  "client_credentials",
			grantTypes: []string{"client_credentials"},
			want:       true,
		},
		{
			name:       "empty grant type remains invalid",
			grantType:  "",
			grantTypes: []string{""},
			want:       false,
		},
		{
			name:       "configured unknown grant remains invalid",
			grantType:  "attacker_defined_grant",
			grantTypes: []string{"attacker_defined_grant"},
			want:       false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsGrantTypeValid(test.grantType, test.grantTypes); got != test.want {
				t.Fatalf("IsGrantTypeValid(%q, %v) = %v, want %v", test.grantType, test.grantTypes, got, test.want)
			}
		})
	}
}

func TestOAuthGrantTypeConfigurationUsesImplementedEnum(t *testing.T) {
	valid := []string{
		"authorization_code",
		"password",
		"client_credentials",
		"token",
		"id_token",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:jwt-bearer",
		"urn:ietf:params:oauth:grant-type:device_code",
		"urn:ietf:params:oauth:grant-type:token-exchange",
	}
	if err := ValidateOAuthGrantTypes(valid); err != nil {
		t.Fatalf("implemented grants rejected: %v", err)
	}
	for _, grants := range [][]string{
		{"attacker_defined_grant"},
		{""},
		{"authorization_code", "authorization_code"},
	} {
		if err := ValidateOAuthGrantTypes(grants); err == nil {
			t.Fatalf("invalid grants accepted: %v", grants)
		}
	}
}

func TestDynamicClientResponseTypesMustMatchExplicitGrantTypes(t *testing.T) {
	for _, test := range []struct {
		name          string
		grantTypes    []string
		responseTypes []string
		wantError     bool
	}{
		{name: "explicit code", grantTypes: []string{"authorization_code"}, responseTypes: []string{"code"}},
		{name: "explicit implicit token", grantTypes: []string{"token"}, responseTypes: []string{"token"}},
		{name: "empty metadata", grantTypes: []string{}, responseTypes: []string{}},
		{name: "code without grant", grantTypes: []string{}, responseTypes: []string{"code"}, wantError: true},
		{name: "mismatched m2m", grantTypes: []string{"client_credentials"}, responseTypes: []string{"code"}, wantError: true},
		{name: "unknown response", grantTypes: []string{"authorization_code"}, responseTypes: []string{"other"}, wantError: true},
		{name: "unknown grant", grantTypes: []string{"other"}, responseTypes: []string{}, wantError: true},
		{name: "duplicate response", grantTypes: []string{"authorization_code"}, responseTypes: []string{"code", "code"}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateDynamicClientOAuthMetadata(test.grantTypes, test.responseTypes)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error = %v, wantError=%v", err, test.wantError)
			}
		})
	}
}

func TestDirectGrantHelpersRejectMissingAllowlistBeforeStateAccess(t *testing.T) {
	application := &Application{Owner: "admin", Name: "no-grants", ClientId: "no-grants-client"}

	codeToken, tokenError, err := GetAuthorizationCodeToken(application, "", "any-code", "", "")
	if err != nil || codeToken != nil || tokenError == nil || tokenError.Error != UnsupportedGrantType {
		t.Fatalf("direct code exchange = (%#v, %#v, %v), want unsupported_grant_type", codeToken, tokenError, err)
	}

	refreshResult, err := RefreshToken(application, "refresh_token", "any-refresh-token", "", application.ClientId, "", "", "")
	if err != nil {
		t.Fatalf("direct refresh returned internal error: %v", err)
	}
	refreshError, ok := refreshResult.(*TokenError)
	if !ok || refreshError.Error != UnsupportedGrantType {
		t.Fatalf("direct refresh = %#v, want unsupported_grant_type", refreshResult)
	}
}

func TestDeviceAuthorizationValidatesGrantAndScopeBeforeStateCreation(t *testing.T) {
	application := &Application{Scopes: []*ScopeItem{{Name: "openid"}}}
	if scope, tokenError := ValidateDeviceAuthorizationRequest(application, "openid"); scope != "" || tokenError == nil || tokenError.Error != UnauthorizedClient {
		t.Fatalf("device auth without grant = (%q, %#v)", scope, tokenError)
	}
	application.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}
	if scope, tokenError := ValidateDeviceAuthorizationRequest(application, "admin"); scope != "" || tokenError == nil || tokenError.Error != InvalidScope {
		t.Fatalf("device auth with invalid scope = (%q, %#v)", scope, tokenError)
	}
	if scope, tokenError := ValidateDeviceAuthorizationRequest(application, "openid"); scope != "openid" || tokenError != nil {
		t.Fatalf("valid device auth = (%q, %#v)", scope, tokenError)
	}
}

func TestIdTokenGrantRequiresNonce(t *testing.T) {
	if tokenError := ValidateOAuthNonceForGrant("id_token", ""); tokenError == nil || tokenError.Error != InvalidRequest {
		t.Fatalf("missing id_token nonce error = %#v", tokenError)
	}
	if tokenError := ValidateOAuthNonceForGrant("id_token", "nonce-value"); tokenError != nil {
		t.Fatalf("valid id_token nonce rejected: %#v", tokenError)
	}
	if tokenError := ValidateOAuthNonceForGrant("token", ""); tokenError != nil {
		t.Fatalf("access-token grant unexpectedly required OIDC nonce: %#v", tokenError)
	}
}

func TestEmptyScopeAllowlistOnlyAcceptsEmptyRequest(t *testing.T) {
	application := &Application{}

	if expanded, ok := IsScopeValidAndExpand("", application); !ok || expanded != "" {
		t.Fatalf("empty scope = (%q, %v), want empty and valid", expanded, ok)
	}
	if expanded, ok := IsScopeValidAndExpand("openid", application); ok || expanded != "" {
		t.Fatalf("openid with empty allowlist = (%q, %v), want empty and invalid", expanded, ok)
	}
	if expanded, ok := IsScopeValidAndExpand("open.*", application); ok || expanded != "" {
		t.Fatalf("regex scope with empty allowlist = (%q, %v), want empty and invalid", expanded, ok)
	}
	if expanded, ok := IsScopeValidAndExpand("openid", nil); ok || expanded != "" {
		t.Fatalf("scope with nil application = (%q, %v), want empty and invalid", expanded, ok)
	}
}

func TestConfiguredScopeAllowlistRemainsExactAndExpandable(t *testing.T) {
	application := &Application{Scopes: []*ScopeItem{
		nil,
		{Name: "openid"},
		{Name: "profile"},
		{Name: "email"},
	}}

	if expanded, ok := IsScopeValidAndExpand("openid profile", application); !ok || expanded != "openid profile" {
		t.Fatalf("allowed scopes = (%q, %v), want exact scopes and valid", expanded, ok)
	}
	if expanded, ok := IsScopeValidAndExpand("unknown", application); ok || expanded != "" {
		t.Fatalf("unknown scope = (%q, %v), want empty and invalid", expanded, ok)
	}
	if expanded, ok := IsScopeValidAndExpand("open.*", application); !ok || expanded != "openid" {
		t.Fatalf("regex scope = (%q, %v), want openid and valid", expanded, ok)
	}
}
