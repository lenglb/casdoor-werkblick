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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	tokenSecurityOrganization = "security-test-org"
	tokenSecurityUserID       = "security-test-user-id"
	tokenSecurityRedirect     = "https://client.example.test/callback"
)

func setupTokenSecurityTestOrmer(t *testing.T) {
	t.Helper()

	previousOrmer := ormer
	databasePath := filepath.Join(t.TempDir(), "tokens.db")
	dataSourceName := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)", databasePath)
	testOrmer, err := NewAdapter("sqlite3", dataSourceName, "")
	if err != nil {
		t.Fatalf("create SQLite adapter: %v", err)
	}
	testOrmer.Engine.SetMaxOpenConns(8)
	if err = testOrmer.Engine.Sync2(new(Token), new(User), new(Organization), new(Permission), new(Role), new(Application), new(Cert), new(Syncer), new(ThirdPartyLink)); err != nil {
		testOrmer.close()
		t.Fatalf("create token security tables: %v", err)
	}
	if _, err = testOrmer.Engine.Insert(&Organization{Owner: "admin", Name: tokenSecurityOrganization}); err != nil {
		testOrmer.close()
		t.Fatalf("insert token security organization: %v", err)
	}
	if _, err = testOrmer.Engine.Insert(&User{Owner: tokenSecurityOrganization, Name: "alice", Id: tokenSecurityUserID, Email: "alice@example.test", EmailVerified: true}); err != nil {
		testOrmer.close()
		t.Fatalf("insert token security user: %v", err)
	}
	ormer = testOrmer

	t.Cleanup(func() {
		ormer = previousOrmer
		testOrmer.close()
	})
}

func TestAuthorizationCodeCanOnlyBeConsumedOnce(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	application := &Application{
		Owner:        "admin",
		Name:         "security-test-app",
		Organization: tokenSecurityOrganization,
		ClientId:     "security-test-client",
		ClientSecret: "security-test-secret",
		GrantTypes:   []string{"authorization_code"},
	}
	token := &Token{
		Owner:                 application.Owner,
		Name:                  "authorization-code-token",
		Application:           application.Name,
		Organization:          tokenSecurityOrganization,
		User:                  "alice",
		Subject:               tokenSecurityUserID,
		Code:                  "single-use-authorization-code",
		CodeIsUsed:            false,
		CodeExpireIn:          time.Now().Add(time.Minute).Unix(),
		TokenType:             "Bearer",
		GrantType:             "authorization_code",
		RedirectUri:           tokenSecurityRedirect,
		AuthTime:              time.Now().Unix(),
		AuthenticationMethods: []string{"pwd"},
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("add token: %v", err)
	}

	const exchanges = 32
	start := make(chan struct{})
	var successes atomic.Int32
	var rejected atomic.Int32
	var unexpected atomic.Int32
	var wg sync.WaitGroup
	wg.Add(exchanges)

	for i := 0; i < exchanges; i++ {
		go func() {
			defer wg.Done()
			<-start
			result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(
				application,
				application.ClientSecret,
				token.Code,
				"",
				tokenSecurityRedirect,
				"",
			)
			switch {
			case err != nil:
				unexpected.Add(1)
			case tokenError != nil && tokenError.Error == InvalidGrant:
				rejected.Add(1)
			case tokenError == nil && result != nil:
				successes.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("successful exchanges = %d, want exactly 1", got)
	}
	if got := rejected.Load(); got != exchanges-1 {
		t.Fatalf("rejected replays = %d, want %d", got, exchanges-1)
	}
	if got := unexpected.Load(); got != 0 {
		t.Fatalf("unexpected exchange results = %d", got)
	}

	stored, err := getTokenByCode(token.Code)
	if err != nil {
		t.Fatalf("reload token: %v", err)
	}
	if stored == nil || !stored.CodeIsUsed {
		t.Fatalf("authorization code was not persisted as consumed: %#v", stored)
	}
}

func TestInvalidAuthorizationCodeRequestDoesNotConsumeCode(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	application := &Application{
		Owner:                   "admin",
		Name:                    "security-test-app",
		Organization:            tokenSecurityOrganization,
		ClientId:                "security-test-client",
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
	}
	verifier := "correct-verifier"
	token := &Token{
		Owner:                 application.Owner,
		Name:                  "pkce-token",
		Application:           application.Name,
		Organization:          tokenSecurityOrganization,
		User:                  "alice",
		Subject:               tokenSecurityUserID,
		Code:                  "pkce-authorization-code",
		CodeChallenge:         pkceChallenge(verifier),
		CodeIsUsed:            false,
		CodeExpireIn:          time.Now().Add(time.Minute).Unix(),
		TokenType:             "Bearer",
		GrantType:             "authorization_code",
		RedirectUri:           tokenSecurityRedirect,
		AuthTime:              time.Now().Unix(),
		AuthenticationMethods: []string{"pwd"},
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("add token: %v", err)
	}

	result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(application, "", token.Code, "wrong-verifier", tokenSecurityRedirect, "")
	if err != nil {
		t.Fatalf("invalid exchange returned internal error: %v", err)
	}
	if result != nil || tokenError == nil || tokenError.Error != InvalidGrant {
		t.Fatalf("invalid exchange = (%#v, %#v), want invalid_grant", result, tokenError)
	}

	stored, err := getTokenByCode(token.Code)
	if err != nil {
		t.Fatalf("reload token: %v", err)
	}
	if stored == nil || stored.CodeIsUsed {
		t.Fatalf("invalid PKCE request consumed the code: %s", fmt.Sprintf("%#v", stored))
	}

	result, tokenError, err = GetAuthorizationCodeTokenWithRedirectUri(application, "", token.Code, verifier, tokenSecurityRedirect, "")
	if err != nil || tokenError != nil || result == nil {
		t.Fatalf("valid exchange after invalid attempt = (%#v, %#v, %v)", result, tokenError, err)
	}
}

func TestConfidentialClientPKCEDoesNotBypassClientSecret(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	application := &Application{
		Owner:        "admin",
		Name:         "confidential-app",
		ClientId:     "confidential-client",
		ClientSecret: "required-secret",
		GrantTypes:   []string{"authorization_code"},
	}
	verifier := "correct-verifier"
	token := &Token{
		Owner:         application.Owner,
		Name:          "confidential-code-token",
		Application:   application.Name,
		Organization:  "security-test-org",
		User:          "alice",
		Code:          "confidential-authorization-code",
		CodeChallenge: pkceChallenge(verifier),
		GrantType:     "authorization_code",
		RedirectUri:   tokenSecurityRedirect,
		CodeExpireIn:  time.Now().Add(time.Minute).Unix(),
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("add token: %v", err)
	}

	result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(application, "", token.Code, verifier, tokenSecurityRedirect, "")
	if err != nil {
		t.Fatalf("exchange returned internal error: %v", err)
	}
	if result != nil || tokenError == nil || tokenError.Error != InvalidClient {
		t.Fatalf("exchange = (%#v, %#v), want invalid_client", result, tokenError)
	}
	stored, err := getTokenByCode(token.Code)
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored.CodeIsUsed {
		t.Fatal("failed confidential-client authentication consumed the code")
	}
}

func TestAuthorizationCodeIsBoundToApplicationOwner(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	issuedApplication := &Application{Owner: "admin", Name: "same-name", ClientSecret: "secret", GrantTypes: []string{"authorization_code"}}
	requestingApplication := &Application{Owner: "other-owner", Name: issuedApplication.Name, ClientSecret: issuedApplication.ClientSecret, GrantTypes: []string{"authorization_code"}}
	token := &Token{
		Owner:        issuedApplication.Owner,
		Name:         "owner-bound-code-token",
		Application:  issuedApplication.Name,
		Organization: "security-test-org",
		User:         "alice",
		Code:         "owner-bound-authorization-code",
		GrantType:    "authorization_code",
		RedirectUri:  tokenSecurityRedirect,
		CodeExpireIn: time.Now().Add(time.Minute).Unix(),
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("add token: %v", err)
	}

	result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(requestingApplication, requestingApplication.ClientSecret, token.Code, "", tokenSecurityRedirect, "")
	if err != nil {
		t.Fatalf("exchange returned internal error: %v", err)
	}
	if result != nil || tokenError == nil || tokenError.Error != InvalidGrant {
		t.Fatalf("exchange = (%#v, %#v), want invalid_grant", result, tokenError)
	}
}

func TestAuthorizationCodeRedemptionRechecksRedirectSubjectUserAndAssurance(t *testing.T) {
	const redirectUri = "https://client.example.test/callback"
	tests := []struct {
		name              string
		requestedRedirect string
		scope             string
		subject           string
		omitSubject       bool
		methods           []string
		mutateUser        func(*User)
		wantError         string
	}{
		{
			name:              "redirect URI mismatch",
			requestedRedirect: "https://attacker.example.test/callback",
			wantError:         "redirect_uri",
		},
		{
			name:              "redirect URI missing",
			requestedRedirect: "",
			wantError:         "redirect_uri",
		},
		{
			name:              "immutable subject mismatch",
			requestedRedirect: redirectUri,
			subject:           "deleted-user-id",
			wantError:         "no longer identifies",
		},
		{
			name:              "immutable subject missing",
			requestedRedirect: redirectUri,
			omitSubject:       true,
			wantError:         "no immutable subject",
		},
		{
			name:              "user forbidden after authorization",
			requestedRedirect: redirectUri,
			mutateUser:        func(user *User) { user.IsForbidden = true },
			wantError:         "forbidden",
		},
		{
			name:              "MFA enabled after AAL1 authorization",
			requestedRedirect: redirectUri,
			mutateUser:        func(user *User) { user.TotpSecret = "newly-enrolled" },
			wantError:         "multi-factor authentication",
		},
		{
			name:              "ordinary unverified email user remains OIDC-compatible",
			requestedRedirect: redirectUri,
			scope:             "email",
			mutateUser:        func(user *User) { user.EmailVerified = false },
		},
		{
			name:              "scope revalidation is order insensitive",
			requestedRedirect: redirectUri,
			scope:             "email openid",
		},
		{
			name:              "server-bound AAL2 remains valid",
			requestedRedirect: redirectUri,
			methods:           []string{"pwd", "otp"},
			mutateUser:        func(user *User) { user.TotpSecret = "enrolled" },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupTokenSecurityTestOrmer(t)
			application := &Application{
				Owner:        "admin",
				Name:         "security-test-app",
				Organization: tokenSecurityOrganization,
				ClientId:     "security-test-client",
				ClientSecret: "security-test-secret",
				GrantTypes:   []string{"authorization_code"},
				Scopes:       []*ScopeItem{{Name: "openid"}, {Name: "email"}},
			}
			user, err := getUser(tokenSecurityOrganization, "alice")
			if err != nil || user == nil {
				t.Fatalf("load user = (%#v, %v)", user, err)
			}
			if test.mutateUser != nil {
				test.mutateUser(user)
				if _, err = ormer.Engine.ID([]interface{}{user.Owner, user.Name}).Cols("is_forbidden", "totp_secret", "email_verified").Update(user); err != nil {
					t.Fatalf("update user: %v", err)
				}
			}
			subject := test.subject
			if subject == "" && !test.omitSubject {
				subject = tokenSecurityUserID
			}
			methods := test.methods
			if len(methods) == 0 {
				methods = []string{"pwd"}
			}
			token := &Token{
				Owner:                 application.Owner,
				Name:                  "bound-code-token",
				Application:           application.Name,
				Organization:          tokenSecurityOrganization,
				User:                  "alice",
				Subject:               subject,
				Code:                  "bound-authorization-code",
				GrantType:             "authorization_code",
				CodeExpireIn:          time.Now().Add(time.Minute).Unix(),
				RedirectUri:           redirectUri,
				Scope:                 test.scope,
				AuthTime:              time.Now().Unix(),
				AuthenticationMethods: methods,
			}
			if _, err = AddToken(token); err != nil {
				t.Fatalf("add token: %v", err)
			}

			result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(application, application.ClientSecret, token.Code, "", test.requestedRedirect, "")
			if err != nil {
				t.Fatalf("exchange returned internal error: %v", err)
			}
			if test.wantError == "" {
				if tokenError != nil || result == nil {
					t.Fatalf("valid exchange = (%#v, %#v)", result, tokenError)
				}
				return
			}
			if result != nil || tokenError == nil || tokenError.Error != InvalidGrant || !strings.Contains(tokenError.ErrorDescription, test.wantError) {
				t.Fatalf("exchange = (%#v, %#v), want invalid_grant containing %q", result, tokenError, test.wantError)
			}
			stored, reloadErr := getTokenByCode(token.Code)
			if reloadErr != nil || stored == nil || stored.CodeIsUsed {
				t.Fatalf("rejected exchange consumed code: (%#v, %v)", stored, reloadErr)
			}
		})
	}
}

func TestRefreshAuthenticationContextCannotRemainAAL1AfterMfaEnrollment(t *testing.T) {
	user := &User{Owner: tokenSecurityOrganization, Name: "alice", Id: tokenSecurityUserID, TotpSecret: "newly-enrolled"}
	token := &Token{
		Organization:          user.Owner,
		User:                  user.Name,
		Subject:               user.Id,
		AuthTime:              time.Now().Unix(),
		AuthenticationMethods: []string{"pwd"},
	}
	authenticationContext, err := token.GetAuthenticationContext()
	if err != nil {
		t.Fatalf("persisted authentication context: %v", err)
	}
	tokenError := validateUserTokenAuthenticationPolicy(user, "openid profile email", authenticationContext)
	if tokenError == nil || tokenError.Error != InvalidGrant || !strings.Contains(tokenError.ErrorDescription, "multi-factor authentication") {
		t.Fatalf("refresh policy error = %#v, want MFA reauthentication", tokenError)
	}
}

func TestRefreshTokenCanOnlyBeRotatedOnce(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	oldToken := &Token{
		Owner:        "admin",
		Name:         "refresh-token",
		Application:  "security-test-app",
		Organization: "security-test-org",
		User:         "alice",
		Code:         "refresh-code",
		AccessToken:  "old-access-token",
		RefreshToken: "single-use-refresh-token",
		CodeIsUsed:   true,
		CodeExpireIn: time.Now().Add(time.Minute).Unix(),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
	if _, err := AddToken(oldToken); err != nil {
		t.Fatalf("add old refresh token: %v", err)
	}

	const rotations = 32
	start := make(chan struct{})
	var successes atomic.Int32
	var rejected atomic.Int32
	var unexpected atomic.Int32
	var wg sync.WaitGroup
	wg.Add(rotations)

	for i := 0; i < rotations; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			newToken := &Token{
				Owner:        oldToken.Owner,
				Name:         fmt.Sprintf("rotated-token-%02d", i),
				Application:  oldToken.Application,
				Organization: oldToken.Organization,
				User:         oldToken.User,
				Code:         fmt.Sprintf("rotated-code-%02d", i),
				AccessToken:  fmt.Sprintf("access-token-%02d", i),
				RefreshToken: fmt.Sprintf("refresh-token-%02d", i),
				CodeIsUsed:   true,
				CodeExpireIn: time.Now().Add(time.Minute).Unix(),
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}
			rotated, err := rotateRefreshToken(oldToken, newToken)
			switch {
			case err != nil:
				unexpected.Add(1)
			case rotated:
				successes.Add(1)
			default:
				rejected.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := successes.Load(); got != 1 {
		t.Fatalf("successful rotations = %d, want exactly 1", got)
	}
	if got := rejected.Load(); got != rotations-1 {
		t.Fatalf("rejected refresh replays = %d, want %d", got, rotations-1)
	}
	if got := unexpected.Load(); got != 0 {
		t.Fatalf("unexpected rotation results = %d", got)
	}

	count, err := ormer.Engine.Count(&Token{})
	if err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 2 {
		t.Fatalf("stored tokens after rotation = %d, want consumed tombstone plus one successor", count)
	}
	storedOld, err := getToken(oldToken.Owner, oldToken.Name)
	if err != nil {
		t.Fatalf("reload old token: %v", err)
	}
	if storedOld == nil || !storedOld.RefreshTokenConsumed || storedOld.ExpiresIn != 0 {
		t.Fatalf("old refresh token was not retained as an inactive reuse tombstone: %#v", storedOld)
	}
}

func TestRefreshRotationRollsBackWhenSuccessorInsertFails(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	oldToken := &Token{
		Owner:        "admin",
		Name:         "old-refresh-token",
		Application:  "security-test-app",
		Organization: "security-test-org",
		User:         "alice",
		AccessToken:  "old-access-token",
		RefreshToken: "old-refresh-token-value",
		CodeIsUsed:   true,
		CodeExpireIn: time.Now().Add(time.Minute).Unix(),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
	collision := &Token{
		Owner:        "admin",
		Name:         "existing-successor",
		Application:  "security-test-app",
		Organization: "security-test-org",
		User:         "alice",
		AccessToken:  "collision-access-token",
		RefreshToken: "collision-refresh-token",
		CodeIsUsed:   true,
		CodeExpireIn: time.Now().Add(time.Minute).Unix(),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
	if _, err := AddToken(oldToken); err != nil {
		t.Fatalf("add old token: %v", err)
	}
	if _, err := AddToken(collision); err != nil {
		t.Fatalf("add collision token: %v", err)
	}

	successor := &Token{
		Owner:        collision.Owner,
		Name:         collision.Name,
		Application:  oldToken.Application,
		Organization: oldToken.Organization,
		User:         oldToken.User,
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		CodeIsUsed:   true,
		CodeExpireIn: time.Now().Add(time.Minute).Unix(),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
	rotated, err := rotateRefreshToken(oldToken, successor)
	if err == nil || rotated {
		t.Fatalf("rotateRefreshToken() = (%v, %v), want insert error and no rotation", rotated, err)
	}

	storedOld, err := getToken(oldToken.Owner, oldToken.Name)
	if err != nil {
		t.Fatalf("reload old token: %v", err)
	}
	if storedOld == nil || storedOld.RefreshToken != oldToken.RefreshToken {
		t.Fatalf("old token was not restored by rollback: %#v", storedOld)
	}
	if storedOld.RefreshTokenConsumed || storedOld.ExpiresIn != oldToken.ExpiresIn {
		t.Fatalf("failed rotation left the original token consumed: %#v", storedOld)
	}
	storedCollision, err := getToken(collision.Owner, collision.Name)
	if err != nil {
		t.Fatalf("reload collision token: %v", err)
	}
	if storedCollision == nil || storedCollision.RefreshToken != collision.RefreshToken {
		t.Fatalf("collision token changed during failed rotation: %#v", storedCollision)
	}
}

func TestRefreshTokenReuseRevokesSuccessorFamily(t *testing.T) {
	setupTokenSecurityTestOrmer(t)

	oldToken := &Token{
		Owner:        "admin",
		Name:         "family-root",
		Application:  "security-test-app",
		Organization: "security-test-org",
		User:         "alice",
		AccessToken:  "family-root-access",
		RefreshToken: "family-root-refresh",
		CodeIsUsed:   true,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
	if _, err := AddToken(oldToken); err != nil {
		t.Fatal(err)
	}
	successor := &Token{
		Owner:        oldToken.Owner,
		Name:         "family-successor",
		Application:  oldToken.Application,
		Organization: oldToken.Organization,
		User:         oldToken.User,
		AccessToken:  "family-successor-access",
		RefreshToken: "family-successor-refresh",
		CodeIsUsed:   true,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
	rotated, err := rotateRefreshToken(oldToken, successor)
	if err != nil || !rotated {
		t.Fatalf("rotateRefreshToken = (%v, %v)", rotated, err)
	}

	consumed, err := GetTokenByRefreshToken(oldToken.RefreshToken)
	if err != nil || consumed == nil || !consumed.RefreshTokenConsumed {
		t.Fatalf("consumed tombstone = (%#v, %v)", consumed, err)
	}
	if err = revokeRefreshTokenFamily(consumed); err != nil {
		t.Fatal(err)
	}
	storedSuccessor, err := getToken(successor.Owner, successor.Name)
	if err != nil {
		t.Fatal(err)
	}
	if storedSuccessor == nil || storedSuccessor.ExpiresIn != 0 {
		t.Fatalf("successor remained active after family reuse: %#v", storedSuccessor)
	}
}

func TestIssuedClientCredentialsDPoPBindingRequiresGrantApplicationAndSubject(t *testing.T) {
	newFixture := func() (*Application, *Token) {
		application := &Application{
			Owner:        "admin",
			Name:         "machine-client",
			Organization: "tenant",
			GrantTypes:   []string{"client_credentials"},
		}
		return application, &Token{
			Owner:        application.Owner,
			Application:  application.Name,
			Organization: application.Organization,
			User:         application.Name,
			Subject:      application.GetId(),
			GrantType:    "client_credentials",
		}
	}

	application, token := newFixture()
	if tokenError := validateIssuedTokenDPoPBinding(application, token); tokenError != nil {
		t.Fatalf("valid client credentials binding was rejected: %#v", tokenError)
	}

	tests := []struct {
		name string
		edit func(*Application, *Token)
		want string
	}{
		{
			name: "immutable subject mismatch",
			edit: func(_ *Application, token *Token) { token.Subject = "admin/replacement-client" },
			want: "does not identify",
		},
		{
			name: "application mismatch",
			edit: func(_ *Application, token *Token) { token.Application = "other-app" },
			want: "does not belong",
		},
		{
			name: "grant disabled",
			edit: func(application *Application, _ *Token) { application.GrantTypes = nil },
			want: "grant is no longer enabled",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			application, token := newFixture()
			test.edit(application, token)
			tokenError := validateIssuedTokenDPoPBinding(application, token)
			if tokenError == nil || tokenError.Error != InvalidGrant || !strings.Contains(tokenError.ErrorDescription, test.want) {
				t.Fatalf("binding error = %#v, want invalid_grant containing %q", tokenError, test.want)
			}
		})
	}
}

func TestIssuedUserDPoPBindingAcceptsMatchingCurrentState(t *testing.T) {
	setupTokenSecurityTestOrmer(t)
	application := &Application{
		Owner:        "admin",
		Name:         "security-test-app",
		Organization: tokenSecurityOrganization,
		GrantTypes:   []string{"password"},
	}
	token := &Token{
		Owner:                 application.Owner,
		Application:           application.Name,
		Organization:          tokenSecurityOrganization,
		User:                  "alice",
		Subject:               tokenSecurityUserID,
		GrantType:             "password",
		AuthTime:              time.Now().Unix(),
		AuthenticationMethods: []string{"pwd"},
	}

	if tokenError := validateIssuedTokenDPoPBinding(application, token); tokenError != nil {
		t.Fatalf("matching token binding was rejected: %#v", tokenError)
	}
	user, authenticationContext, tokenError, err := revalidateIssuedUserTokenForDPoP(application, token)
	if err != nil || tokenError != nil {
		t.Fatalf("matching user binding = (%#v, %v)", tokenError, err)
	}
	if user == nil || user.Id != tokenSecurityUserID || authenticationContext.Subject != user.GetId() {
		t.Fatalf("matching user binding returned unexpected state: user=%#v context=%#v", user, authenticationContext)
	}
}

func TestIssuedUserDPoPBindingRevalidatesSubjectAccessAndMfa(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testing.T, *Application, *Token)
		want      string
	}{
		{
			name: "immutable subject mismatch",
			configure: func(_ *testing.T, _ *Application, token *Token) {
				token.Subject = "replacement-user-id"
			},
			want: "no longer identifies",
		},
		{
			name: "application access disabled",
			configure: func(_ *testing.T, application *Application, _ *Token) {
				application.DisableSignin = true
			},
			want: "application has disabled",
		},
		{
			name: "MFA enabled after initial mint",
			configure: func(t *testing.T, _ *Application, _ *Token) {
				affected, err := ormer.Engine.
					Where("owner = ? AND name = ?", tokenSecurityOrganization, "alice").
					Cols("totp_secret").
					Update(&User{TotpSecret: "enrolled-after-mint"})
				if err != nil || affected != 1 {
					t.Fatalf("enable persisted MFA = (%d, %v)", affected, err)
				}
			},
			want: "multi-factor authentication",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupTokenSecurityTestOrmer(t)
			application := &Application{
				Owner:        "admin",
				Name:         "security-test-app",
				Organization: tokenSecurityOrganization,
				GrantTypes:   []string{"password"},
			}
			token := &Token{
				Owner:                 application.Owner,
				Application:           application.Name,
				Organization:          tokenSecurityOrganization,
				User:                  "alice",
				Subject:               tokenSecurityUserID,
				GrantType:             "password",
				AuthTime:              time.Now().Unix(),
				AuthenticationMethods: []string{"pwd"},
			}
			test.configure(t, application, token)

			user, _, tokenError, err := revalidateIssuedUserTokenForDPoP(application, token)
			if err != nil {
				t.Fatalf("revalidation returned internal error: %v", err)
			}
			if user != nil || tokenError == nil || tokenError.Error != InvalidGrant || !strings.Contains(tokenError.ErrorDescription, test.want) {
				t.Fatalf("revalidation = (%#v, %#v), want invalid_grant containing %q", user, tokenError, test.want)
			}
		})
	}
}

func TestGuestAuthorizationRequiresExactRegisteredRedirect(t *testing.T) {
	setupTokenSecurityTestOrmer(t)
	application := &Application{
		Owner:             "admin",
		Name:              "guest-app",
		Organization:      tokenSecurityOrganization,
		ClientSecret:      "guest-secret",
		GrantTypes:        []string{"authorization_code"},
		RedirectUris:      []string{tokenSecurityRedirect},
		EnableGuestSignin: true,
		EnableSignUp:      true,
	}

	for _, redirectUri := range []string{"", "https://attacker.example.test/callback"} {
		result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(application, application.ClientSecret, "guest-user", "", redirectUri, "")
		if err != nil {
			t.Fatalf("redirect %q returned internal error: %v", redirectUri, err)
		}
		if result != nil || tokenError == nil || tokenError.Error != InvalidGrant || !strings.Contains(tokenError.ErrorDescription, "exact registered redirect_uri") {
			t.Fatalf("redirect %q result = (%#v, %#v), want invalid_grant", redirectUri, result, tokenError)
		}
	}

	application.GrantTypes = nil
	result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(application, application.ClientSecret, "guest-user", "", tokenSecurityRedirect, "")
	if err != nil {
		t.Fatalf("disabled grant returned internal error: %v", err)
	}
	if result != nil || tokenError == nil || tokenError.Error != UnsupportedGrantType {
		t.Fatalf("disabled grant result = (%#v, %#v), want unsupported_grant_type", result, tokenError)
	}
}

func TestGuestAuthorizationRevalidatesAccessAndMfaBeforeCreatingUser(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testing.T, *Application)
		want      string
	}{
		{
			name: "application sign-in disabled",
			configure: func(_ *testing.T, application *Application) {
				application.DisableSignin = true
			},
			want: "application has disabled",
		},
		{
			name: "required MFA enrollment missing",
			configure: func(t *testing.T, _ *Application) {
				affected, err := ormer.Engine.
					Where("owner = ? AND name = ?", "admin", tokenSecurityOrganization).
					Cols("mfa_items").
					Update(&Organization{MfaItems: []*MfaItem{{Name: TotpType, Rule: "Required"}}})
				if err != nil || affected != 1 {
					t.Fatalf("require organization MFA = (%d, %v)", affected, err)
				}
			},
			want: "required MFA enrollment",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setupTokenSecurityTestOrmer(t)
			application := &Application{
				Owner:             "admin",
				Name:              "guest-app",
				Organization:      tokenSecurityOrganization,
				ClientSecret:      "guest-secret",
				GrantTypes:        []string{"authorization_code"},
				RedirectUris:      []string{tokenSecurityRedirect},
				EnableGuestSignin: true,
				EnableSignUp:      true,
			}
			test.configure(t, application)

			result, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(application, application.ClientSecret, "guest-user", "", tokenSecurityRedirect, "")
			if err != nil {
				t.Fatalf("guest authorization returned internal error: %v", err)
			}
			if result != nil || tokenError == nil || tokenError.Error != InvalidGrant || !strings.Contains(tokenError.ErrorDescription, test.want) {
				t.Fatalf("guest authorization = (%#v, %#v), want invalid_grant containing %q", result, tokenError, test.want)
			}
			count, countErr := ormer.Engine.Where("tag = ?", "guest-user").Count(new(User))
			if countErr != nil || count != 0 {
				t.Fatalf("denied guest authorization created %d users: %v", count, countErr)
			}
		})
	}
}

func TestGuestAuthorizationHappyPathPersistsBoundUserAndToken(t *testing.T) {
	setupTokenSecurityTestOrmer(t)
	certificate, privateKey, err := generateRsaKeys(2048, 512, 20, "guest-test-cert", "security-test")
	if err != nil {
		t.Fatalf("generate guest signing key: %v", err)
	}
	cert := &Cert{
		Owner:       "admin",
		Name:        "guest-test-cert",
		Certificate: certificate,
		PrivateKey:  privateKey,
	}
	if _, err = ormer.Engine.Insert(cert); err != nil {
		t.Fatalf("insert guest signing certificate: %v", err)
	}
	application := &Application{
		Owner:                "admin",
		Name:                 "guest-app",
		Organization:         tokenSecurityOrganization,
		ClientId:             "guest-client",
		ClientSecret:         "guest-secret",
		Cert:                 cert.Name,
		ExpireInHours:        1,
		RefreshExpireInHours: 1,
		GrantTypes:           []string{"authorization_code"},
		RedirectUris:         []string{tokenSecurityRedirect},
		EnableGuestSignin:    true,
		EnableSignUp:         true,
	}
	if _, err = ormer.Engine.Insert(application); err != nil {
		t.Fatalf("insert guest application: %v", err)
	}

	token, tokenError, err := GetAuthorizationCodeTokenWithRedirectUri(
		application,
		application.ClientSecret,
		"guest-user",
		"",
		tokenSecurityRedirect,
		"",
	)
	if err != nil || tokenError != nil {
		t.Fatalf("guest authorization = (%#v, %v)", tokenError, err)
	}
	if token == nil || token.Subject == "" || token.RedirectUri != tokenSecurityRedirect {
		t.Fatalf("guest token is missing immutable redirect binding: %#v", token)
	}

	guestUser, err := getUser(token.Organization, token.User)
	if err != nil {
		t.Fatalf("reload guest user: %v", err)
	}
	if guestUser == nil || guestUser.Id == "" || guestUser.Id != token.Subject || guestUser.Tag != "guest-user" {
		t.Fatalf("persisted guest user does not match token subject: %#v", guestUser)
	}
	authenticationContext, err := token.GetAuthenticationContext()
	if err != nil {
		t.Fatalf("read guest authentication context: %v", err)
	}
	if authenticationContext.Subject != guestUser.GetId() || authenticationContext.AuthTime <= 0 || len(authenticationContext.Amr) != 1 || authenticationContext.Amr[0] != "guest" {
		t.Fatalf("guest authentication context is incomplete: %#v", authenticationContext)
	}

	persistedToken, err := getToken(token.Owner, token.Name)
	if err != nil {
		t.Fatalf("reload guest token: %v", err)
	}
	if persistedToken == nil || persistedToken.Subject != guestUser.Id || persistedToken.RedirectUri != tokenSecurityRedirect {
		t.Fatalf("persisted guest token lost subject or redirect binding: %#v", persistedToken)
	}
	persistedContext, err := persistedToken.GetAuthenticationContext()
	if err != nil || persistedContext.Subject != guestUser.GetId() || len(persistedContext.Amr) != 1 || persistedContext.Amr[0] != "guest" {
		t.Fatalf("persisted guest authentication context = (%#v, %v)", persistedContext, err)
	}
}

func TestFailedPostMintDPoPBindingDeletesIssuedBearerToken(t *testing.T) {
	setupTokenSecurityTestOrmer(t)
	application := &Application{
		Owner:        "admin",
		Name:         "different-application",
		Organization: tokenSecurityOrganization,
		GrantTypes:   []string{"password"},
	}
	token := &Token{
		Owner:        "admin",
		Name:         "failed-dpop-binding",
		Application:  "security-test-app",
		Organization: tokenSecurityOrganization,
		User:         "alice",
		Subject:      tokenSecurityUserID,
		AccessToken:  "unreturned-bearer-token",
		TokenType:    "Bearer",
		GrantType:    "password",
		ExpiresIn:    3600,
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("persist issued bearer token: %v", err)
	}

	tokenError, err := bindIssuedTokenToDPoPWithCleanup(application, token, "test-dpop-thumbprint", "", "", nil)
	if err != nil {
		t.Fatalf("failed DPoP binding returned internal error: %v", err)
	}
	if tokenError == nil || tokenError.Error != InvalidGrant {
		t.Fatalf("failed DPoP binding error = %#v, want invalid_grant", tokenError)
	}
	persisted, err := getToken(token.Owner, token.Name)
	if err != nil {
		t.Fatalf("reload cleaned token: %v", err)
	}
	if persisted != nil {
		t.Fatalf("failed DPoP binding left a persisted bearer token: %#v", persisted)
	}
}

func TestFailedPostMintDPoPBindingCleanupFailsClosed(t *testing.T) {
	setupTokenSecurityTestOrmer(t)
	application := &Application{
		Owner:        "admin",
		Name:         "different-application",
		Organization: tokenSecurityOrganization,
		GrantTypes:   []string{"password"},
	}
	token := &Token{
		Owner:        "admin",
		Name:         "missing-issued-token",
		Organization: tokenSecurityOrganization,
	}
	if tokenError, err := bindIssuedTokenToDPoPWithCleanup(application, token, "test-dpop-thumbprint", "", "", nil); err == nil || tokenError != nil {
		t.Fatal("missing issued token row was treated as successfully cleaned")
	}
}

func TestFailedDeviceDPoPBindingOnlyAllowsRetryAfterTokenCleanup(t *testing.T) {
	setupTokenSecurityTestOrmer(t)
	previousStore := DeviceAuthMap
	store := &memoryDeviceAuthStore{}
	DeviceAuthMap = store
	t.Cleanup(func() { DeviceAuthMap = previousStore })

	now := time.Now()
	cache := approvedDeviceAuthCache(now)
	store.Store("retryable-device-code", cache)
	claimed, result := ClaimDeviceAuthTokenIssuance("retryable-device-code", cache.ApplicationId, cache.ClientId, now.Add(time.Second))
	if result != DeviceAuthTokenClaimed {
		t.Fatalf("device claim = %q, want %q", result, DeviceAuthTokenClaimed)
	}
	token := &Token{
		Owner:        "admin",
		Name:         "failed-device-dpop-binding",
		Application:  "device-app",
		Organization: tokenSecurityOrganization,
		User:         "alice",
		Subject:      tokenSecurityUserID,
		AccessToken:  "unreturned-device-bearer",
		TokenType:    "Bearer",
		GrantType:    "urn:ietf:params:oauth:grant-type:device_code",
		ExpiresIn:    3600,
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("persist device bearer token: %v", err)
	}
	if err := cleanupFailedPostMintDPoPBinding("retryable-device-code", &claimed, token); err != nil {
		t.Fatalf("cleanup device DPoP failure: %v", err)
	}
	if persisted, err := getToken(token.Owner, token.Name); err != nil || persisted != nil {
		t.Fatalf("device cleanup left token = (%#v, %v)", persisted, err)
	}
	if _, result = ClaimDeviceAuthTokenIssuance("retryable-device-code", cache.ApplicationId, cache.ClientId, now.Add(2*time.Second)); result != DeviceAuthTokenClaimed {
		t.Fatalf("device retry after cleanup = %q, want %q", result, DeviceAuthTokenClaimed)
	}

	store.Store("locked-device-code", cache)
	lockedClaim, result := ClaimDeviceAuthTokenIssuance("locked-device-code", cache.ApplicationId, cache.ClientId, now.Add(time.Second))
	if result != DeviceAuthTokenClaimed {
		t.Fatalf("locked device claim = %q, want %q", result, DeviceAuthTokenClaimed)
	}
	missingToken := &Token{Owner: "admin", Name: "missing-device-token", Organization: tokenSecurityOrganization}
	if err := cleanupFailedPostMintDPoPBinding("locked-device-code", &lockedClaim, missingToken); err == nil {
		t.Fatal("missing device token row was treated as successfully cleaned")
	}
	if _, result = ClaimDeviceAuthTokenIssuance("locked-device-code", cache.ApplicationId, cache.ClientId, now.Add(2*time.Second)); result != DeviceAuthTokenIssuanceInProgress {
		t.Fatalf("device retry after cleanup failure = %q, want %q", result, DeviceAuthTokenIssuanceInProgress)
	}
}
