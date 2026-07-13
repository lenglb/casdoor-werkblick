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

package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestResolveUserUpdateFieldsSeparatesSelfAndAdmin(t *testing.T) {
	fields, explicit, err := resolveUserUpdateFields("displayName,email", false)
	if err != nil || !explicit || len(fields) != 2 || fields[0].column != "display_name" || fields[1].column != "email" {
		t.Fatalf("legitimate self profile fields = %+v explicit=%v err=%v", fields, explicit, err)
	}

	for _, column := range []string{"emailVerified", "isAdmin", "webauthnCredentials", "ldap", "password", "totpSecret", "groups", "unknown"} {
		if _, _, err = resolveUserUpdateFields(column, false); err == nil {
			t.Fatalf("self-service column %q unexpectedly allowed", column)
		}
	}

	fields, _, err = resolveUserUpdateFields("isAdmin,groups", true)
	if err != nil || len(fields) != 2 || fields[0].column != "is_admin" || fields[1].column != "groups" {
		t.Fatalf("legitimate admin fields = %+v err=%v", fields, err)
	}
	for _, column := range []string{"emailVerified", "webauthnCredentials", "ldap", "password", "recoveryCodes", "applicationScopes"} {
		if _, _, err = resolveUserUpdateFields(column, true); err == nil {
			t.Fatalf("generic admin column %q unexpectedly allowed", column)
		}
	}
}

func TestResolveUserUpdateFieldsRejectsAmbiguousColumnLists(t *testing.T) {
	for _, columns := range []string{"displayName, displayName", "displayName,displayName", ",displayName", "displayName,"} {
		if _, _, err := resolveUserUpdateFields(columns, false); err == nil {
			t.Fatalf("ambiguous columns %q unexpectedly allowed", columns)
		}
	}
}

func TestBuildUserUpdateCandidateProjectsOnlyAllowedFields(t *testing.T) {
	oldUser := &object.User{
		Owner:         "tenant",
		Name:          "alice",
		DisplayName:   "Alice",
		Email:         "old@example.com",
		EmailVerified: true,
		IsAdmin:       false,
		Ldap:          "ldap-server",
	}
	fields, explicit, err := resolveUserUpdateFields("displayName", false)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := buildUserUpdateCandidate(oldUser, []byte(`{
		"displayName":"Alice Updated",
		"emailVerified":false,
		"isAdmin":true,
		"ldap":"attacker-controlled"
	}`), fields, explicit)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.DisplayName != "Alice Updated" {
		t.Fatalf("displayName = %q", candidate.DisplayName)
	}
	if candidate.IsAdmin || !candidate.EmailVerified || candidate.Ldap != oldUser.Ldap {
		t.Fatalf("sensitive fields crossed projection boundary: %+v", candidate)
	}

	if _, err = buildUserUpdateCandidate(oldUser, []byte(`{"email":"new@example.com"}`), fields, explicit); err == nil {
		t.Fatal("explicit displayName update without displayName body field unexpectedly succeeded")
	}
}
