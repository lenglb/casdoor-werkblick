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
	"encoding/json"
	"strings"
	"testing"
)

func TestMaskedUserNeverReturnsBearerCredentialsToSelfOrAdmin(t *testing.T) {
	for _, isAdminOrSelf := range []bool{false, true} {
		user := &User{
			Owner:                "tenant",
			Name:                 "alice",
			AccessToken:          "account-access-token-sentinel",
			OriginalToken:        "original-token-sentinel",
			OriginalRefreshToken: "original-refresh-token-sentinel",
			Properties: map[string]string{
				"oauth_google_accessToken": "provider-access-token-sentinel",
				"OAuth_Custom_Profile":     "provider-response-sentinel",
				"department":               "production",
			},
		}
		masked, err := GetMaskedUser(user, isAdminOrSelf)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(masked)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{
			"account-access-token-sentinel", "original-token-sentinel", "original-refresh-token-sentinel",
			"provider-access-token-sentinel", "provider-response-sentinel",
		} {
			if strings.Contains(string(payload), secret) {
				t.Fatalf("masked user (isAdminOrSelf=%v) exposed %q", isAdminOrSelf, secret)
			}
		}
		if masked.Properties["department"] != "production" {
			t.Fatal("masking removed a non-OAuth profile property")
		}
	}
}
