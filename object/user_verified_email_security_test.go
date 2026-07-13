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
	"reflect"
	"testing"
)

func setupVerifiedEmailSecurityTestOrmer(t *testing.T) {
	t.Helper()

	previousOrmer := ormer
	databasePath := filepath.Join(t.TempDir(), "verified-email.db")
	testOrmer, err := NewAdapter("sqlite3", fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)", databasePath), "")
	if err != nil {
		t.Fatalf("create SQLite adapter: %v", err)
	}
	if err = testOrmer.Engine.Sync2(new(User), new(Syncer)); err != nil {
		testOrmer.close()
		t.Fatalf("create user table: %v", err)
	}
	ormer = testOrmer
	t.Cleanup(func() {
		ormer = previousOrmer
		testOrmer.close()
	})
}

func insertVerifiedEmailSecurityUser(t *testing.T, user *User) {
	t.Helper()
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("insert user: %v", err)
	}
}

func TestVerifiedEmailChallengeUpdatePreservesVerificationAtomically(t *testing.T) {
	setupVerifiedEmailSecurityTestOrmer(t)
	insertVerifiedEmailSecurityUser(t, &User{
		Owner:         "security-org",
		Name:          "alice",
		Id:            "alice-id",
		Email:         "old@example.com",
		EmailVerified: true,
	})

	updated, err := UpdateUserEmailFromVerifiedChallenge("security-org/alice", "verified@example.com", false)
	if err != nil {
		t.Fatalf("verified challenge update: %v", err)
	}
	if updated.Email != "verified@example.com" || !updated.EmailVerified {
		t.Fatalf("verified challenge result = (%q, %v), want verified address", updated.Email, updated.EmailVerified)
	}

	stored, err := getUser("security-org", "alice")
	if err != nil {
		t.Fatalf("reload verified user: %v", err)
	}
	if stored == nil || stored.Email != "verified@example.com" || !stored.EmailVerified {
		t.Fatalf("stored verified challenge result = %#v", stored)
	}

	stored.Email = "generic@example.com"
	stored.EmailVerified = true
	if _, err = UpdateUser(stored.GetId(), stored, []string{"email", "email_verified"}, false); err != nil {
		t.Fatalf("generic email update: %v", err)
	}
	stored, err = getUser("security-org", "alice")
	if err != nil {
		t.Fatalf("reload generic update: %v", err)
	}
	if stored == nil || stored.Email != "generic@example.com" || stored.EmailVerified {
		t.Fatalf("generic update retained verification: %#v", stored)
	}
}

func TestVerifiedEmailMfaChallengePersistsBoundAddressAndEnrollmentTogether(t *testing.T) {
	setupVerifiedEmailSecurityTestOrmer(t)
	insertVerifiedEmailSecurityUser(t, &User{
		Owner:         "security-org",
		Name:          "bob",
		Id:            "bob-id",
		Email:         "unverified@example.com",
		EmailVerified: false,
		RecoveryCodes: []string{"existing-code"},
	})

	updated, err := EnableUserEmailMfaFromVerifiedChallenge(
		"security-org/bob",
		"mfa-verified@example.com",
		[]string{"new-code"},
	)
	if err != nil {
		t.Fatalf("enable verified email MFA: %v", err)
	}
	if updated.Email != "mfa-verified@example.com" || !updated.EmailVerified || !updated.MfaEmailEnabled {
		t.Fatalf("verified email MFA result = %#v", updated)
	}

	stored, err := getUser("security-org", "bob")
	if err != nil {
		t.Fatalf("reload email MFA user: %v", err)
	}
	if stored == nil || stored.Email != "mfa-verified@example.com" || !stored.EmailVerified || !stored.MfaEmailEnabled {
		t.Fatalf("stored email MFA result = %#v", stored)
	}
	if stored.PreferredMfaType != EmailType {
		t.Fatalf("preferred MFA type = %q, want %q", stored.PreferredMfaType, EmailType)
	}
	if !reflect.DeepEqual(stored.RecoveryCodes, []string{"existing-code", "new-code"}) {
		t.Fatalf("recovery codes = %v", stored.RecoveryCodes)
	}
}

func TestVerifiedEmailChallengeApisRejectInvalidAddressesWithoutWriting(t *testing.T) {
	setupVerifiedEmailSecurityTestOrmer(t)
	insertVerifiedEmailSecurityUser(t, &User{Owner: "security-org", Name: "carol", Email: "old@example.com", EmailVerified: true})

	if _, err := UpdateUserEmailFromVerifiedChallenge("security-org/carol", "not an email", false); err == nil {
		t.Fatal("invalid verified email was accepted")
	}
	if _, err := EnableUserEmailMfaFromVerifiedChallenge("security-org/carol", "not an email", []string{"code"}); err == nil {
		t.Fatal("invalid verified MFA email was accepted")
	}
	stored, err := getUser("security-org", "carol")
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.Email != "old@example.com" || !stored.EmailVerified || stored.MfaEmailEnabled {
		t.Fatalf("invalid challenge mutated user: %#v", stored)
	}
}

func TestAllFieldsUserUpdateCannotCarryVerificationToChangedEmail(t *testing.T) {
	setupVerifiedEmailSecurityTestOrmer(t)
	insertVerifiedEmailSecurityUser(t, &User{
		Owner:         "security-org",
		Name:          "dave",
		Id:            "dave-id",
		Email:         "old@example.com",
		EmailVerified: true,
	})
	candidate, err := getUser("security-org", "dave")
	if err != nil || candidate == nil {
		t.Fatalf("load candidate = (%#v, %v)", candidate, err)
	}
	candidate.Email = "changed-by-all-fields@example.com"
	candidate.EmailVerified = true
	if _, err = UpdateUserForAllFields(candidate.GetId(), candidate); err != nil {
		t.Fatalf("all-fields update: %v", err)
	}
	stored, err := getUser("security-org", "dave")
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.Email != candidate.Email || stored.EmailVerified {
		t.Fatalf("all-fields update retained stale email verification: %#v", stored)
	}
}
