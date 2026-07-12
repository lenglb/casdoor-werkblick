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
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	if err = testOrmer.Engine.Sync2(new(Token)); err != nil {
		testOrmer.close()
		t.Fatalf("create token table: %v", err)
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
		ClientId:     "security-test-client",
		ClientSecret: "security-test-secret",
	}
	token := &Token{
		Owner:        application.Owner,
		Name:         "authorization-code-token",
		Application:  application.Name,
		Organization: "security-test-org",
		User:         "alice",
		Code:         "single-use-authorization-code",
		CodeIsUsed:   false,
		CodeExpireIn: time.Now().Add(time.Minute).Unix(),
		TokenType:    "Bearer",
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
			result, tokenError, err := GetAuthorizationCodeToken(
				application,
				application.ClientSecret,
				token.Code,
				"",
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
		ClientId:                "security-test-client",
		TokenEndpointAuthMethod: "none",
	}
	verifier := "correct-verifier"
	token := &Token{
		Owner:         application.Owner,
		Name:          "pkce-token",
		Application:   application.Name,
		Organization:  "security-test-org",
		User:          "alice",
		Code:          "pkce-authorization-code",
		CodeChallenge: pkceChallenge(verifier),
		CodeIsUsed:    false,
		CodeExpireIn:  time.Now().Add(time.Minute).Unix(),
		TokenType:     "Bearer",
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("add token: %v", err)
	}

	result, tokenError, err := GetAuthorizationCodeToken(application, "", token.Code, "wrong-verifier", "")
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

	result, tokenError, err = GetAuthorizationCodeToken(application, "", token.Code, verifier, "")
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
		CodeExpireIn:  time.Now().Add(time.Minute).Unix(),
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("add token: %v", err)
	}

	result, tokenError, err := GetAuthorizationCodeToken(application, "", token.Code, verifier, "")
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

	issuedApplication := &Application{Owner: "admin", Name: "same-name", ClientSecret: "secret"}
	requestingApplication := &Application{Owner: "other-owner", Name: issuedApplication.Name, ClientSecret: issuedApplication.ClientSecret}
	token := &Token{
		Owner:        issuedApplication.Owner,
		Name:         "owner-bound-code-token",
		Application:  issuedApplication.Name,
		Organization: "security-test-org",
		User:         "alice",
		Code:         "owner-bound-authorization-code",
		CodeExpireIn: time.Now().Add(time.Minute).Unix(),
	}
	if _, err := AddToken(token); err != nil {
		t.Fatalf("add token: %v", err)
	}

	result, tokenError, err := GetAuthorizationCodeToken(requestingApplication, requestingApplication.ClientSecret, token.Code, "", "")
	if err != nil {
		t.Fatalf("exchange returned internal error: %v", err)
	}
	if result != nil || tokenError == nil || tokenError.Error != InvalidGrant {
		t.Fatalf("exchange = (%#v, %#v), want invalid_grant", result, tokenError)
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
