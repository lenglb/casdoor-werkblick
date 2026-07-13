//go:build werkblick_e2e_seed

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
	"os"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
)

// TestSeedWerkblickE2EAdmin prepares only the isolated Cypress database. The
// build tag keeps this mutation helper out of production binaries and ordinary
// test runs, so the secure random-and-forbidden first-start administrator stays
// the sole runtime default.
func TestSeedWerkblickE2EAdmin(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" ||
		os.Getenv("GITHUB_REPOSITORY") != "lenglb/casdoor-werkblick" ||
		os.Getenv("GITHUB_WORKFLOW") != "Build" ||
		os.Getenv("GITHUB_JOB") != "e2e" ||
		os.Getenv("WERKBLICK_E2E_SEED_SCOPE") != "github-actions-cypress" {
		t.Fatal("isolated E2E seed is restricted to the fork's Cypress job")
	}
	password := os.Getenv("WERKBLICK_E2E_ADMIN_PASSWORD")
	if len(password) < 32 || strings.TrimSpace(password) != password {
		t.Fatal("WERKBLICK_E2E_ADMIN_PASSWORD must be an unpadded value of at least 32 characters")
	}

	if err := web.LoadAppConfig("ini", "../conf/app.conf"); err != nil {
		t.Fatalf("load isolated E2E configuration: %v", err)
	}
	if conf.GetConfigString("driverName") != "mysql" ||
		conf.GetConfigDataSourceName() != "root:123456@tcp(localhost:3306)/" ||
		conf.GetConfigString("dbName") != "casdoor" ||
		conf.GetConfigString("tableNamePrefix") != "" {
		t.Fatal("isolated E2E seed refused a non-CI database target")
	}

	// The workflow service already provisions this exact empty database.
	// Matching normal server startup avoids a second CREATE DATABASE attempt.
	createDatabase = false
	InitAdapter()
	CreateTables()
	if err := ensureInitDataImportTargetEmpty(); err != nil {
		t.Fatalf("isolated E2E seed refused a non-empty database: %v", err)
	}
	InitDb()

	user, err := getUser("built-in", "admin")
	if err != nil {
		t.Fatalf("load isolated E2E administrator: %v", err)
	}
	if user == nil || !user.IsAdmin || user.IsDeleted || !user.IsForbidden ||
		!user.NeedUpdatePassword || user.Password == "" || user.Password == "123" {
		t.Fatal("isolated E2E administrator did not start in the secure forbidden state")
	}
	previousPassword := user.Password
	previousPasswordSalt := user.PasswordSalt

	organization, err := GetOrganizationByUser(user)
	if err != nil || organization == nil {
		t.Fatalf("load isolated E2E organization: %v", err)
	}
	user.Password = password
	user.UpdateUserPassword(organization)
	user.IsForbidden = false
	user.NeedUpdatePassword = false
	user.LastChangePasswordTime = util.GetCurrentTime()
	if changed, updateErr := UpdateUser(
		user.GetId(),
		user,
		[]string{
			"password", "password_type", "password_salt", "is_forbidden",
			"need_update_password", "last_change_password_time",
		},
		true,
	); updateErr != nil || !changed {
		t.Fatalf("activate isolated E2E administrator: changed=%v err=%v", changed, updateErr)
	}

	seeded, err := getUser("built-in", "admin")
	if err != nil || seeded == nil || !seeded.IsAdmin || seeded.IsDeleted ||
		seeded.Password == password || seeded.Password == previousPassword ||
		seeded.PasswordType != organization.PasswordType || seeded.PasswordSalt == "" ||
		seeded.PasswordSalt == previousPasswordSalt || seeded.IsForbidden ||
		seeded.NeedUpdatePassword || seeded.LastChangePasswordTime == "" {
		t.Fatalf("verify isolated E2E administrator: err=%v", err)
	}
	if authenticated, passwordErr := CheckUserPassword(
		"built-in", "admin", password, "en", false, false, false,
	); passwordErr != nil || authenticated == nil {
		t.Fatalf("verify isolated E2E credential: %v", passwordErr)
	}
	for _, invalidPassword := range []string{"Werkblick-E2E-fixed-invalid-password", "123"} {
		if authenticated, passwordErr := CheckUserPassword(
			"built-in", "admin", invalidPassword, "en", false, false, false,
		); passwordErr == nil || authenticated != nil {
			t.Fatalf("isolated E2E administrator accepted an invalid credential")
		}
	}
}
