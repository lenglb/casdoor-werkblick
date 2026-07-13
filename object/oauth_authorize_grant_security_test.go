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
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupOAuthAuthorizeGrantTestOrmer(t *testing.T) {
	t.Helper()

	previousOrmer := ormer
	databasePath := filepath.Join(t.TempDir(), "oauth-authorize.db")
	testOrmer, err := NewAdapter("sqlite3", fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)", databasePath), "")
	if err != nil {
		t.Fatalf("create SQLite adapter: %v", err)
	}
	if err = testOrmer.Engine.Sync2(new(Application), new(Organization), new(Provider), new(Token)); err != nil {
		testOrmer.close()
		t.Fatalf("create OAuth authorize tables: %v", err)
	}
	ormer = testOrmer
	t.Cleanup(func() {
		ormer = previousOrmer
		testOrmer.close()
	})
}

func TestCheckOAuthLoginRequiresExplicitGrantForResponseType(t *testing.T) {
	setupOAuthAuthorizeGrantTestOrmer(t)
	application := &Application{
		Owner:        "admin",
		Name:         "no-browser-grants",
		Organization: "security-org",
		ClientId:     "no-browser-grants-client",
		RedirectUris: []string{"https://client.example.test/callback"},
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []*ScopeItem{{Name: "openid"}},
	}
	if _, err := ormer.Engine.Insert(application); err != nil {
		t.Fatalf("insert application: %v", err)
	}

	msg, loaded, err := CheckOAuthLogin(
		application.ClientId,
		"code",
		application.RedirectUris[0],
		"openid",
		"state",
		"en",
	)
	if err != nil {
		t.Fatalf("CheckOAuthLogin: %v", err)
	}
	if loaded == nil || !strings.Contains(msg, "authorization_code") {
		t.Fatalf("authorization request = (%q, %#v), want explicit grant rejection", msg, loaded)
	}

	application.GrantTypes = []string{"authorization_code"}
	if _, err = ormer.Engine.ID([]interface{}{application.Owner, application.Name}).Cols("grant_types").Update(application); err != nil {
		t.Fatalf("enable authorization_code: %v", err)
	}
	msg, loaded, err = CheckOAuthLogin(
		application.ClientId,
		"code",
		application.RedirectUris[0],
		"openid",
		"state",
		"en",
	)
	if err != nil || msg != "" || loaded == nil {
		t.Fatalf("explicit authorization_code request = (%q, %#v, %v)", msg, loaded, err)
	}
}

func TestGetOAuthCodeRejectsMissingAuthorizationCodeGrantBeforeIssuance(t *testing.T) {
	setupOAuthAuthorizeGrantTestOrmer(t)
	application := &Application{
		Owner:        "admin",
		Name:         "m2m-only",
		Organization: "security-org",
		ClientId:     "m2m-only-client",
		RedirectUris: []string{"https://client.example.test/callback"},
		GrantTypes:   []string{"client_credentials"},
	}
	if _, err := ormer.Engine.Insert(application); err != nil {
		t.Fatalf("insert application: %v", err)
	}

	code, err := GetOAuthCodeWithAuthenticationContext(
		"security-org/user-does-not-need-to-exist",
		application.ClientId,
		AuthenticationContext{Subject: "security-org/user-does-not-need-to-exist", AuthTime: time.Now().Unix(), Amr: []string{"pwd"}},
		"code",
		application.RedirectUris[0],
		"",
		"state",
		"nonce",
		"challenge",
		"",
		"id.example.test",
		"en",
	)
	if err != nil {
		t.Fatalf("GetOAuthCodeWithAuthenticationContext: %v", err)
	}
	if code == nil || code.Code != "" || !strings.Contains(code.Message, "authorization_code") {
		t.Fatalf("code result = %#v, want pre-issuance grant rejection", code)
	}
	count, err := ormer.Engine.Count(new(Token))
	if err != nil {
		t.Fatalf("count issued tokens: %v", err)
	}
	if count != 0 {
		t.Fatalf("issued tokens = %d, want 0", count)
	}
}
