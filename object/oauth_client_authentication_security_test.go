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

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateOAuthClientAuthenticationEnforcesRegisteredMethod(t *testing.T) {
	secretApplication := &Application{
		ClientId:                "client-id",
		ClientSecret:            "client-secret",
		TokenEndpointAuthMethod: ClientAuthMethodSecretBasic,
	}

	tests := []struct {
		name           string
		application    *Application
		authentication *OAuthClientAuthentication
		wantError      bool
	}{
		{
			name:        "basic succeeds only for basic registration",
			application: secretApplication,
			authentication: &OAuthClientAuthentication{
				Method:       ClientAuthMethodSecretBasic,
				ClientId:     secretApplication.ClientId,
				ClientSecret: secretApplication.ClientSecret,
			},
		},
		{
			name: "post succeeds only for post registration",
			application: &Application{
				ClientId:                "post-client",
				ClientSecret:            "post-secret",
				TokenEndpointAuthMethod: ClientAuthMethodSecretPost,
			},
			authentication: &OAuthClientAuthentication{
				Method:       ClientAuthMethodSecretPost,
				ClientId:     "post-client",
				ClientSecret: "post-secret",
			},
		},
		{
			name:        "post cannot downgrade basic registration",
			application: secretApplication,
			authentication: &OAuthClientAuthentication{
				Method:       ClientAuthMethodSecretPost,
				ClientId:     secretApplication.ClientId,
				ClientSecret: secretApplication.ClientSecret,
			},
			wantError: true,
		},
		{
			name: "basic cannot substitute for post registration",
			application: &Application{
				ClientId:                "post-client",
				ClientSecret:            "post-secret",
				TokenEndpointAuthMethod: ClientAuthMethodSecretPost,
			},
			authentication: &OAuthClientAuthentication{
				Method:       ClientAuthMethodSecretBasic,
				ClientId:     "post-client",
				ClientSecret: "post-secret",
			},
			wantError: true,
		},
		{
			name: "public client accepts no credentials",
			application: &Application{
				ClientId:                "public-client",
				TokenEndpointAuthMethod: ClientAuthMethodNone,
			},
			authentication: &OAuthClientAuthentication{
				Method:   ClientAuthMethodNone,
				ClientId: "public-client",
			},
		},
		{
			name: "public client rejects a secret",
			application: &Application{
				ClientId:                "public-client",
				TokenEndpointAuthMethod: ClientAuthMethodNone,
			},
			authentication: &OAuthClientAuthentication{
				Method:       ClientAuthMethodNone,
				ClientId:     "public-client",
				ClientSecret: "unexpected",
			},
			wantError: true,
		},
		{
			name: "private key client rejects a shared secret",
			application: &Application{
				ClientId:                "assertion-client",
				TokenEndpointAuthMethod: ClientAuthMethodPrivateKeyJwt,
			},
			authentication: &OAuthClientAuthentication{
				Method:              ClientAuthMethodPrivateKeyJwt,
				ClientId:            "assertion-client",
				ClientSecret:        "unexpected",
				ClientAssertion:     "assertion",
				ClientAssertionType: ClientAssertionTypeJwtBearer,
			},
			wantError: true,
		},
		{
			name: "private key assertion failures stay generic",
			application: &Application{
				Owner:                   "admin",
				ClientId:                "assertion-client",
				TokenEndpointAuthMethod: ClientAuthMethodPrivateKeyJwt,
			},
			authentication: &OAuthClientAuthentication{
				Method:              ClientAuthMethodPrivateKeyJwt,
				ClientId:            "assertion-client",
				ClientAssertion:     "not-a-jwt",
				ClientAssertionType: ClientAssertionTypeJwtBearer,
			},
			wantError: true,
		},
		{
			name:        "wrong secret fails",
			application: secretApplication,
			authentication: &OAuthClientAuthentication{
				Method:       ClientAuthMethodSecretBasic,
				ClientId:     secretApplication.ClientId,
				ClientSecret: "wrong",
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tokenError := validateOAuthClientAuthentication(test.application, test.authentication, "id.example.test")
			if gotError := tokenError != nil; gotError != test.wantError {
				t.Fatalf("validateOAuthClientAuthentication() error = %#v, wantError %v", tokenError, test.wantError)
			}
			if test.name == "private key assertion failures stay generic" && tokenError.ErrorDescription != "client assertion is invalid" {
				t.Fatalf("private_key_jwt error description = %q, want generic response", tokenError.ErrorDescription)
			}
		})
	}
}

func TestValidateClientAssertionClaimsRequiresBoundedOneShotAssertion(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	application := &Application{ClientId: "assertion-client"}
	origin := "https://id.example.test"

	validClaims := func() *Claims {
		return &Claims{RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    application.ClientId,
			Subject:   application.ClientId,
			Audience:  jwt.ClaimStrings{origin + "/api/login/oauth/access_token"},
			ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "assertion-id",
		}}
	}

	tests := []struct {
		name   string
		mutate func(*Claims)
	}{
		{name: "missing exp", mutate: func(claims *Claims) { claims.ExpiresAt = nil }},
		{name: "missing iat", mutate: func(claims *Claims) { claims.IssuedAt = nil }},
		{name: "missing jti", mutate: func(claims *Claims) { claims.ID = "" }},
		{name: "wrong issuer", mutate: func(claims *Claims) { claims.Issuer = "redirect-uri" }},
		{name: "wrong subject", mutate: func(claims *Claims) { claims.Subject = "other-client" }},
		{name: "wrong audience", mutate: func(claims *Claims) { claims.Audience = jwt.ClaimStrings{"https://other.test/token"} }},
		{name: "multiple audiences", mutate: func(claims *Claims) { claims.Audience = append(claims.Audience, "https://other.test") }},
		{name: "stale iat", mutate: func(claims *Claims) {
			claims.IssuedAt = jwt.NewNumericDate(now.Add(-clientAssertionMaxLifetime - time.Second))
		}},
		{name: "future iat", mutate: func(claims *Claims) {
			claims.IssuedAt = jwt.NewNumericDate(now.Add(clientAssertionFutureSkew + time.Second))
		}},
		{name: "expired", mutate: func(claims *Claims) { claims.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Second)) }},
		{name: "excess lifetime", mutate: func(claims *Claims) {
			claims.ExpiresAt = jwt.NewNumericDate(now.Add(clientAssertionMaxLifetime + time.Second))
		}},
		{name: "oversized jti", mutate: func(claims *Claims) { claims.ID = strings.Repeat("x", clientAssertionMaxJtiBytes+1) }},
	}

	if err := validateClientAssertionClaims(application, validClaims(), origin, now, false); err != nil {
		t.Fatalf("valid assertion claims rejected: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validClaims()
			test.mutate(claims)
			if err := validateClientAssertionClaims(application, claims, origin, now, false); err == nil {
				t.Fatal("invalid assertion claims were accepted")
			}
		})
	}
}

func TestClientAssertionReplayIsAtomic(t *testing.T) {
	previousStore := globalClientAssertionReplayStore
	globalClientAssertionReplayStore = newMemoryClientAssertionReplayStore(clientAssertionReplayMaxEntries)
	t.Cleanup(func() { globalClientAssertionReplayStore = previousStore })

	now := time.Now()
	application := &Application{ClientId: "assertion-client"}
	claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    application.ClientId,
		Subject:   application.ClientId,
		Audience:  jwt.ClaimStrings{"https://id.example.test/api/login/oauth/access_token"},
		ExpiresAt: jwt.NewNumericDate(now.Add(2 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        "one-shot-id",
	}}

	const attempts = 32
	start := make(chan struct{})
	var accepted atomic.Int32
	var rejected atomic.Int32
	var waitGroup sync.WaitGroup
	waitGroup.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer waitGroup.Done()
			<-start
			err := validateClientAssertionClaims(application, claims, "https://id.example.test", now, true)
			if err == nil {
				accepted.Add(1)
			} else if strings.Contains(err.Error(), "already been used") {
				rejected.Add(1)
			}
		}()
	}
	close(start)
	waitGroup.Wait()

	if accepted.Load() != 1 || rejected.Load() != attempts-1 {
		t.Fatalf("accepted = %d, rejected = %d; want 1/%d", accepted.Load(), rejected.Load(), attempts-1)
	}
}

func TestMemoryClientAssertionReplayStoreIsBoundedAndFailsClosed(t *testing.T) {
	store := newMemoryClientAssertionReplayStore(2)
	now := time.Unix(1_750_000_000, 0)
	store.now = func() time.Time { return now }

	for _, key := range []string{"first", "second"} {
		if used, err := store.Use(key, time.Minute); err != nil || !used {
			t.Fatalf("seed %s = (%v, %v)", key, used, err)
		}
	}
	if used, err := store.Use("third", time.Minute); err == nil || used {
		t.Fatalf("Use at capacity = (%v, %v), want fail-closed error", used, err)
	}

	now = now.Add(time.Minute + time.Second)
	if used, err := store.Use("third", time.Minute); err != nil || !used {
		t.Fatalf("Use after expiration = (%v, %v), want accepted", used, err)
	}
}

func TestDynamicPrivateKeyJwtClientNeverGetsSharedSecret(t *testing.T) {
	previousOrmer := ormer
	databasePath := filepath.Join(t.TempDir(), "oauth-clients.db")
	testOrmer, err := NewAdapter("sqlite3", fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)", databasePath), "")
	if err != nil {
		t.Fatalf("create SQLite adapter: %v", err)
	}
	if err = testOrmer.Engine.Sync2(new(Application), new(Organization), new(Provider)); err != nil {
		testOrmer.close()
		t.Fatalf("create OAuth client tables: %v", err)
	}
	ormer = testOrmer
	t.Cleanup(func() {
		ormer = previousOrmer
		testOrmer.close()
	})

	if _, err = testOrmer.Engine.Insert(&Organization{Owner: "admin", Name: "security-org", DcrPolicy: "open"}); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	response, dcrError, err := RegisterDynamicClient(&DynamicClientRegistrationRequest{
		ClientName:              "private key client",
		RedirectUris:            []string{"https://client.example.test/callback"},
		TokenEndpointAuthMethod: ClientAuthMethodPrivateKeyJwt,
	}, "security-org", "https://id.example.test/api/register")
	if err != nil || dcrError != nil {
		t.Fatalf("RegisterDynamicClient() = (%#v, %#v, %v)", response, dcrError, err)
	}
	if response.ClientSecret != "" {
		t.Fatalf("DCR response exposed private_key_jwt client secret %q", response.ClientSecret)
	}

	stored := &Application{}
	exists, err := testOrmer.Engine.Where("client_id = ?", response.ClientId).Get(stored)
	if err != nil || !exists {
		t.Fatalf("load DCR application = (%v, %v)", exists, err)
	}
	if stored.ClientSecret != "" {
		t.Fatalf("stored private_key_jwt client secret = %q, want empty", stored.ClientSecret)
	}

	secretResponse, dcrError, err := RegisterDynamicClient(&DynamicClientRegistrationRequest{
		ClientName:              "rotated private key client",
		RedirectUris:            []string{"https://rotated.example.test/callback"},
		TokenEndpointAuthMethod: ClientAuthMethodSecretBasic,
	}, "security-org", "https://id.example.test/api/register")
	if err != nil || dcrError != nil || secretResponse.ClientSecret == "" {
		t.Fatalf("register initial secret client = (%#v, %#v, %v)", secretResponse, dcrError, err)
	}
	secretApplication, err := GetApplicationByClientId(secretResponse.ClientId)
	if err != nil || secretApplication == nil {
		t.Fatalf("load initial secret client = (%#v, %v)", secretApplication, err)
	}
	updatedResponse, dcrError, err := UpdateDynamicClient(secretApplication, &DynamicClientRegistrationRequest{
		RedirectUris:            secretApplication.RedirectUris,
		TokenEndpointAuthMethod: ClientAuthMethodPrivateKeyJwt,
	})
	if err != nil || dcrError != nil {
		t.Fatalf("update to private_key_jwt = (%#v, %#v, %v)", updatedResponse, dcrError, err)
	}
	if updatedResponse.ClientSecret != "" {
		t.Fatalf("updated DCR response retained client secret %q", updatedResponse.ClientSecret)
	}
	stored = &Application{}
	exists, err = testOrmer.Engine.Where("client_id = ?", secretResponse.ClientId).Get(stored)
	if err != nil || !exists || stored.ClientSecret != "" {
		t.Fatalf("stored updated private_key_jwt client = (%#v, %v, %v), want empty secret", stored, exists, err)
	}
}
