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
	"testing"
)

func setupUserInfoSecurityTestOrmer(t *testing.T) {
	t.Helper()

	previousOrmer := ormer
	databasePath := filepath.Join(t.TempDir(), "userinfo.db")
	dataSourceName := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)", databasePath)
	testOrmer, err := NewAdapter("sqlite3", dataSourceName, "")
	if err != nil {
		t.Fatalf("create SQLite adapter: %v", err)
	}
	if err = testOrmer.Engine.Sync2(new(Application), new(Organization), new(Provider)); err != nil {
		testOrmer.close()
		t.Fatalf("create userinfo tables: %v", err)
	}
	ormer = testOrmer

	application := &Application{
		Owner:    "admin",
		Name:     "userinfo-security",
		ClientId: "userinfo-client",
	}
	if _, err = testOrmer.Engine.Insert(application); err != nil {
		testOrmer.close()
		t.Fatalf("insert userinfo application: %v", err)
	}

	t.Cleanup(func() {
		ormer = previousOrmer
		testOrmer.close()
	})
}

func TestGetUserInfoPropagatesActualEmailVerification(t *testing.T) {
	setupUserInfoSecurityTestOrmer(t)

	for _, verified := range []bool{false, true} {
		t.Run(fmt.Sprintf("verified-%v", verified), func(t *testing.T) {
			user := &User{
				Id:            "subject",
				Email:         "alice@example.com",
				EmailVerified: verified,
			}
			userinfo, err := GetUserInfo(user, "openid email", "userinfo-client", "id.example.com")
			if err != nil {
				t.Fatal(err)
			}
			if userinfo.Email != user.Email {
				t.Fatalf("email = %q, want %q", userinfo.Email, user.Email)
			}
			if userinfo.EmailVerified != verified {
				t.Fatalf("email_verified = %v, want persisted value %v", userinfo.EmailVerified, verified)
			}
		})
	}
}
