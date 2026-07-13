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

func setupTokenAccessTestOrmer(t *testing.T) {
	t.Helper()

	previousOrmer := ormer
	databasePath := filepath.Join(t.TempDir(), "token-access.db")
	dataSourceName := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)", databasePath)
	testOrmer, err := NewAdapter("sqlite3", dataSourceName, "")
	if err != nil {
		t.Fatalf("create SQLite adapter: %v", err)
	}
	if err = testOrmer.Engine.Sync2(new(User), new(Organization), new(Permission)); err != nil {
		testOrmer.close()
		t.Fatalf("create token access tables: %v", err)
	}
	ormer = testOrmer

	t.Cleanup(func() {
		ormer = previousOrmer
		testOrmer.close()
	})
}

func TestSessionBoundUserTokenMintRequiresGrantScopeAndActiveUser(t *testing.T) {
	context := AuthenticationContext{Subject: "tenant/alice", AuthTime: time.Now().Unix(), Amr: []string{"pwd"}}
	user := &User{Owner: "tenant", Name: "alice", Id: "user-1"}
	application := &Application{Owner: "admin", Name: "app", Organization: "tenant"}

	if _, err := GetTokenByUserForGrantWithAuthenticationContext(application, user, "authorization_code", "profile", "", "", context); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("missing grant error = %v", err)
	}
	application.GrantTypes = []string{"authorization_code"}
	if _, err := GetTokenByUserForGrantWithAuthenticationContext(application, user, "authorization_code", "profile", "", "", context); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("missing scope error = %v", err)
	}

	setupTokenAccessTestOrmer(t)
	user.IsForbidden = true
	organization := &Organization{Owner: "admin", Name: "tenant"}
	insertTokenAccessFixtures(t, user, organization)
	application.Scopes = []*ScopeItem{{Name: "profile"}}
	if _, err := GetTokenByUserForGrantWithAuthenticationContext(application, user, "authorization_code", "profile", "", "", context); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("forbidden user mint error = %v", err)
	}
}

func TestLegacyUserTokenMintWithoutExplicitGrantFailsClosed(t *testing.T) {
	context := AuthenticationContext{Subject: "tenant/alice", AuthTime: time.Now().Unix(), Amr: []string{"pwd"}}
	application := &Application{Owner: "admin", Name: "app", GrantTypes: []string{"token"}}
	user := &User{Owner: "tenant", Name: "alice", Id: "user-1"}

	if _, err := GetTokenByUserWithAuthenticationContext(application, user, "", "", "", context); err == nil || !strings.Contains(err.Error(), "explicit OAuth grant") {
		t.Fatalf("legacy context mint error = %v, want explicit grant rejection", err)
	}
}

func TestHumanTokenPolicyRequiresAAL2OnlyWhenMfaIsEnabled(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name    string
		user    *User
		scope   string
		context AuthenticationContext
		want    string
	}{
		{
			name:    "non-MFA password remains AAL1-compatible",
			user:    &User{Owner: "tenant", Name: "alice", Id: "user-1"},
			context: AuthenticationContext{Subject: "tenant/alice", AuthTime: now, Amr: []string{"pwd"}},
		},
		{
			name:    "MFA password grant cannot bypass second factor",
			user:    &User{Owner: "tenant", Name: "alice", Id: "user-1", TotpSecret: "enrolled"},
			context: AuthenticationContext{Subject: "tenant/alice", AuthTime: now, Amr: []string{"pwd"}},
			want:    "multi-factor authentication",
		},
		{
			name:    "MFA JWT assertion cannot bypass second factor",
			user:    &User{Owner: "tenant", Name: "alice", Id: "user-1", TotpSecret: "enrolled"},
			context: AuthenticationContext{Subject: "tenant/alice", AuthTime: now, Amr: []string{"jwt"}},
			want:    "multi-factor authentication",
		},
		{
			name:    "server-bound AAL2 satisfies MFA",
			user:    &User{Owner: "tenant", Name: "alice", Id: "user-1", TotpSecret: "enrolled"},
			context: AuthenticationContext{Subject: "tenant/alice", AuthTime: now, Amr: []string{"pwd", "otp"}},
		},
		{
			name:    "ordinary OIDC user may expose truthful unverified claim",
			user:    &User{Owner: "tenant", Name: "alice", Id: "user-1", Email: "alice@example.test", EmailVerified: false},
			scope:   "openid email",
			context: AuthenticationContext{Subject: "tenant/alice", AuthTime: now, Amr: []string{"pwd"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokenError := validateUserTokenAuthenticationPolicy(test.user, test.scope, test.context)
			if test.want == "" {
				if tokenError != nil {
					t.Fatalf("policy rejected valid context: %#v", tokenError)
				}
				return
			}
			if tokenError == nil || tokenError.Error != InvalidGrant || !strings.Contains(tokenError.ErrorDescription, test.want) {
				t.Fatalf("policy error = %#v, want invalid_grant containing %q", tokenError, test.want)
			}
		})
	}
}

func insertTokenAccessFixtures(t *testing.T, user *User, organization *Organization) {
	t.Helper()
	if _, err := ormer.Engine.Insert(organization); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("insert user: %v", err)
	}
}

func requireTokenAccessDenied(t *testing.T, application *Application, user *User, descriptionFragment string) {
	t.Helper()
	freshUser, tokenError, err := revalidateUserTokenAccess(application, user)
	if err != nil {
		t.Fatalf("revalidate access returned internal error: %v", err)
	}
	if freshUser != nil {
		t.Fatalf("revalidate access returned user on denial: %#v", freshUser)
	}
	if tokenError == nil || tokenError.Error != InvalidGrant {
		t.Fatalf("revalidate access error = %#v, want invalid_grant", tokenError)
	}
	if !strings.Contains(tokenError.ErrorDescription, descriptionFragment) {
		t.Fatalf("error description %q does not contain %q", tokenError.ErrorDescription, descriptionFragment)
	}
}

func TestTokenIssuanceAccessReloadsUserBeforeCheckingPolicy(t *testing.T) {
	setupTokenAccessTestOrmer(t)

	persistedUser := &User{Owner: "tenant", Name: "alice", Id: "user-1", Tag: "production"}
	organization := &Organization{Owner: "admin", Name: "tenant"}
	insertTokenAccessFixtures(t, persistedUser, organization)

	application := &Application{Owner: "admin", Name: "app", Organization: organization.Name, Tags: []string{"production"}}
	staleUser := &User{Owner: persistedUser.Owner, Name: persistedUser.Name, Id: persistedUser.Id, Tag: "stale-tag", IsForbidden: true}

	freshUser, tokenError, err := revalidateUserTokenAccess(application, staleUser)
	if err != nil || tokenError != nil {
		t.Fatalf("revalidate access = (%#v, %v), want allowed", tokenError, err)
	}
	if freshUser == nil || freshUser.Tag != persistedUser.Tag || freshUser.IsForbidden {
		t.Fatalf("revalidate access did not return persisted user: %#v", freshUser)
	}
}

func TestTokenIssuanceAccessRejectsOffboardedAndRecreatedUsers(t *testing.T) {
	tests := []struct {
		name                 string
		persistedUser        *User
		previouslyLoadedUser *User
		wantDescription      string
	}{
		{
			name:                 "deleted",
			persistedUser:        &User{Owner: "tenant", Name: "alice", Id: "user-1", IsDeleted: true},
			previouslyLoadedUser: &User{Owner: "tenant", Name: "alice", Id: "user-1"},
			wantDescription:      "deleted",
		},
		{
			name:                 "forbidden",
			persistedUser:        &User{Owner: "tenant", Name: "alice", Id: "user-1", IsForbidden: true},
			previouslyLoadedUser: &User{Owner: "tenant", Name: "alice", Id: "user-1"},
			wantDescription:      "forbidden",
		},
		{
			name:                 "username reused",
			persistedUser:        &User{Owner: "tenant", Name: "alice", Id: "replacement-user"},
			previouslyLoadedUser: &User{Owner: "tenant", Name: "alice", Id: "original-user"},
			wantDescription:      "no longer identifies",
		},
		{
			name:                 "missing immutable ID",
			persistedUser:        &User{Owner: "tenant", Name: "alice"},
			previouslyLoadedUser: &User{Owner: "tenant", Name: "alice"},
			wantDescription:      "immutable subject ID",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupTokenAccessTestOrmer(t)
			organization := &Organization{Owner: "admin", Name: "tenant"}
			insertTokenAccessFixtures(t, test.persistedUser, organization)
			application := &Application{Owner: "admin", Name: "app", Organization: organization.Name}
			requireTokenAccessDenied(t, application, test.previouslyLoadedUser, test.wantDescription)
		})
	}
}

func TestTokenIssuanceAccessRejectsDisabledApplicationOrganizationAndTag(t *testing.T) {
	tests := []struct {
		name            string
		application     *Application
		organization    *Organization
		user            *User
		wantDescription string
	}{
		{
			name:            "application disabled",
			application:     &Application{Owner: "admin", Name: "app", Organization: "tenant", DisableSignin: true},
			organization:    &Organization{Owner: "admin", Name: "tenant"},
			user:            &User{Owner: "tenant", Name: "alice", Id: "user-1"},
			wantDescription: "application",
		},
		{
			name:            "organization disabled",
			application:     &Application{Owner: "admin", Name: "app", Organization: "tenant"},
			organization:    &Organization{Owner: "admin", Name: "tenant", DisableSignin: true},
			user:            &User{Owner: "tenant", Name: "alice", Id: "user-1"},
			wantDescription: "organization",
		},
		{
			name:            "tag mismatch",
			application:     &Application{Owner: "admin", Name: "app", Organization: "tenant", Tags: []string{"production"}},
			organization:    &Organization{Owner: "admin", Name: "tenant"},
			user:            &User{Owner: "tenant", Name: "alice", Id: "user-1", Tag: "contractor"},
			wantDescription: "tag",
		},
		{
			name:            "required MFA enrollment incomplete",
			application:     &Application{Owner: "admin", Name: "app", Organization: "tenant"},
			organization:    &Organization{Owner: "admin", Name: "tenant", MfaItems: []*MfaItem{{Name: TotpType, Rule: "Required"}}},
			user:            &User{Owner: "tenant", Name: "alice", Id: "user-1"},
			wantDescription: "required MFA enrollment",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupTokenAccessTestOrmer(t)
			insertTokenAccessFixtures(t, test.user, test.organization)
			requireTokenAccessDenied(t, test.application, test.user, test.wantDescription)
		})
	}
}

func TestTokenIssuanceAccessRechecksApplicationPermissions(t *testing.T) {
	setupTokenAccessTestOrmer(t)

	user := &User{Owner: "tenant", Name: "alice", Id: "user-1"}
	organization := &Organization{Owner: "admin", Name: "tenant"}
	insertTokenAccessFixtures(t, user, organization)
	application := &Application{Owner: "admin", Name: "app", Organization: organization.Name}

	// An enabled Allow permission for this application makes access deny by
	// default when the current user is not one of its subjects.
	permission := &Permission{
		Owner:        organization.Name,
		Name:         "selected-users-only",
		ResourceType: "Application",
		Resources:    []string{application.Name},
		Effect:       "Allow",
		IsEnabled:    true,
		State:        "Approved",
	}
	if _, err := ormer.Engine.Insert(permission); err != nil {
		t.Fatalf("insert permission: %v", err)
	}

	requireTokenAccessDenied(t, application, user, "not authorized")
}
