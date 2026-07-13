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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsGrantTypeValid(test.grantType, test.grantTypes); got != test.want {
				t.Fatalf("IsGrantTypeValid(%q, %v) = %v, want %v", test.grantType, test.grantTypes, got, test.want)
			}
		})
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
