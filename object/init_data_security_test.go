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
	"os"
	"path/filepath"
	"testing"
)

func TestInitFromFileRequiredRejectsMissingInput(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing-init-data.json")} {
		t.Run(path, func(t *testing.T) {
			t.Setenv("initDataFile", path)
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatalf("missing initDataFile %q did not fail closed", path)
				}
			}()
			InitFromFileRequired()
		})
	}
}

func TestInitFromFileRequiredRejectsEmptyObjectBeforeDatabaseAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-init-data.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("initDataFile", path)
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("empty init-data object was reported as successful")
		}
	}()
	InitFromFileRequired()
}

func TestSecureBootstrapSemanticValidationRequiresNonDefaultAdmin(t *testing.T) {
	secure := &InitData{
		Organizations: []*Organization{{Owner: "admin", Name: "built-in"}},
		Applications: []*Application{{
			Owner:        "admin",
			Name:         "app-built-in",
			Organization: "built-in",
			GrantTypes:   []string{"authorization_code"},
		}},
		Users: []*User{{
			Owner:        "built-in",
			Name:         "admin",
			Password:     "$2a$12$secure-hash-placeholder",
			PasswordType: "bcrypt",
			IsAdmin:      true,
		}},
	}
	if err := validateInitData(secure, true); err != nil {
		t.Fatalf("secure bootstrap rejected: %v", err)
	}

	for _, password := range []string{"", "123", "***"} {
		secure.Users[0].Password = password
		if err := validateInitData(secure, true); err == nil {
			t.Fatalf("insecure built-in admin password %q was accepted", password)
		}
	}
	secure.Users[0].Password = "$2a$12$secure-hash-placeholder"
	secure.Applications[0].GrantTypes = []string{"attacker-grant"}
	if err := validateInitData(secure, true); err == nil {
		t.Fatal("bootstrap application with unsupported grant was accepted")
	}
}

func TestDestructiveInitImportRejectsNonEmptyDatabase(t *testing.T) {
	previousOrmer := ormer
	databasePath := filepath.Join(t.TempDir(), "nonempty-init-target.db")
	testOrmer, err := NewAdapter("sqlite3", fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)", databasePath), "")
	if err != nil {
		t.Fatal(err)
	}
	beans := make([]interface{}, 0, len(initDataImportTargets()))
	for _, target := range initDataImportTargets() {
		beans = append(beans, target.bean)
	}
	if err = testOrmer.Engine.Sync2(beans...); err != nil {
		testOrmer.close()
		t.Fatal(err)
	}
	ormer = testOrmer
	t.Cleanup(func() {
		ormer = previousOrmer
		testOrmer.close()
	})

	if err = ensureInitDataImportTargetEmpty(); err != nil {
		t.Fatalf("empty target rejected: %v", err)
	}
	if _, err = testOrmer.Engine.Insert(&Organization{Owner: "admin", Name: "existing"}); err != nil {
		t.Fatal(err)
	}
	if err = ensureInitDataImportTargetEmpty(); err == nil {
		t.Fatal("destructive init import accepted a non-empty database")
	}
}
