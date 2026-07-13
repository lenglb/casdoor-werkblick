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

func TestNormalizeDynamicClientScopesPersistsOnlyLiteralDeduplicatedTokens(t *testing.T) {
	items, normalized, err := normalizeDynamicClientScopes("openid profile files:read openid")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "openid profile files:read" {
		t.Fatalf("normalized scope = %q", normalized)
	}
	if len(items) != 3 || items[0].Name != "openid" || items[1].Name != "profile" || items[2].Name != "files:read" {
		t.Fatalf("scope items = %#v", items)
	}
}

func TestNormalizeDynamicClientScopesRejectsRegexEmptyAndUnsafeTokens(t *testing.T) {
	for _, scope := range []string{
		"openid  profile",
		" openid",
		"openid ",
		"openid\tprofile",
		"openid\nprofile",
		"open.*",
		"files[read]",
		"scope?",
		"scope\\name",
		"scope name!",
	} {
		t.Run(scope, func(t *testing.T) {
			if _, _, err := normalizeDynamicClientScopes(scope); err == nil {
				t.Fatalf("unsafe DCR scope %q was accepted", scope)
			}
		})
	}

	items, normalized, err := normalizeDynamicClientScopes("")
	if err != nil || len(items) != 0 || normalized != "" {
		t.Fatalf("empty scope contract = (%#v, %q, %v), want explicit empty allowlist", items, normalized, err)
	}
}
