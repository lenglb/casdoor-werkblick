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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTokenSecurityTestClaims(user *User) Claims {
	now := time.Unix(1_700_000_000, 0).UTC()
	return Claims{
		User:         user,
		TokenType:    "access-token",
		Nonce:        "nonce-value",
		Scope:        "openid profile",
		Azp:          "client-id",
		Provider:     "provider-name",
		SigninMethod: "Password",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-id",
			Audience:  []string{"client-id"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "token-id",
		},
	}
}

func claimsAsMap(t *testing.T, claims interface{}) map[string]interface{} {
	t.Helper()

	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	res := map[string]interface{}{}
	if err = json.Unmarshal(data, &res); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return res
}

func TestFullJwtClaimsDoNotContainCredentialMaterial(t *testing.T) {
	user := &User{
		Owner:                "owner",
		Name:                 "alice",
		Id:                   "user-id",
		Password:             "password-hash-sentinel",
		PasswordSalt:         "password-salt-sentinel",
		PasswordType:         "password-type-sentinel",
		Hash:                 "sync-hash-sentinel",
		PreHash:              "sync-prehash-sentinel",
		AccessToken:          "access-token-sentinel",
		OriginalToken:        "original-token-sentinel",
		OriginalRefreshToken: "original-refresh-token-sentinel",
		TotpSecret:           "totp-secret-sentinel",
		RecoveryCodes:        []string{"recovery-code-sentinel"},
		ManagedAccounts: []ManagedAccount{{
			Application: "app",
			Username:    "managed-user",
			Password:    "managed-password-sentinel",
		}},
		MfaAccounts: []MfaAccount{{
			AccountName: "alice",
			SecretKey:   "mfa-account-secret-sentinel",
		}},
		Properties: map[string]string{
			"department":                     "production",
			"oauth_GitHub_accessToken":       "oauth-access-token-sentinel",
			"OAUTH_GITHUB_REFRESHTOKEN":      "oauth-refresh-token-sentinel",
			"oauth_GitHub_unrelatedProperty": "oauth-extra-sentinel",
			"oauth_GitHub_extra":             "oauth-provider-response-sentinel",
		},
	}

	safeUser := refineUser(user)
	payload := claimsAsMap(t, getClaimsWithoutThirdIdp(newTokenSecurityTestClaims(safeUser)))
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"password", "passwordSalt", "passwordType", "hash", "preHash", "recoveryCodes",
		"totpSecret", "managedAccounts",
	} {
		if _, ok := payload[key]; ok {
			t.Errorf("full JWT contains credential field %q", key)
		}
	}

	for _, sentinel := range []string{
		"password-hash-sentinel", "password-salt-sentinel", "sync-hash-sentinel",
		"sync-prehash-sentinel", "access-token-sentinel", "original-token-sentinel",
		"original-refresh-token-sentinel", "totp-secret-sentinel", "recovery-code-sentinel",
		"managed-password-sentinel", "mfa-account-secret-sentinel", "oauth-access-token-sentinel",
		"oauth-refresh-token-sentinel", "oauth-extra-sentinel", "oauth-provider-response-sentinel",
	} {
		if strings.Contains(string(encoded), sentinel) {
			t.Errorf("full JWT contains credential sentinel %q", sentinel)
		}
	}

	properties, ok := payload["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("properties claim has unexpected type: %T", payload["properties"])
	}
	if got := properties["department"]; got != "production" {
		t.Errorf("safe property was lost: got %v", got)
	}
	for property := range properties {
		if strings.HasPrefix(strings.ToLower(property), "oauth_") {
			t.Errorf("credential-bearing OAuth property was emitted: %q", property)
		}
	}

	// Sanitizing claims must not mutate the persisted user object.
	if user.Password != "password-hash-sentinel" || user.TotpSecret != "totp-secret-sentinel" {
		t.Fatal("refineUser mutated the source user")
	}
	if user.Properties["oauth_GitHub_accessToken"] != "oauth-access-token-sentinel" {
		t.Fatal("refineUser mutated the source properties")
	}
}

func TestJwtCustomDoesNotExposeDisallowedUserFields(t *testing.T) {
	user := &User{
		Owner:                "owner",
		Name:                 "alice",
		Id:                   "user-id",
		Password:             "password-sentinel",
		PasswordSalt:         "password-salt-sentinel",
		AccessToken:          "access-token-sentinel",
		OriginalToken:        "original-token-sentinel",
		OriginalRefreshToken: "original-refresh-token-sentinel",
		TotpSecret:           "totp-secret-sentinel",
		RecoveryCodes:        []string{"recovery-code-sentinel"},
		ManagedAccounts:      []ManagedAccount{{Password: "managed-password-sentinel"}},
		MfaAccounts:          []MfaAccount{{SecretKey: "mfa-account-secret-sentinel"}},
		InvitationCode:       "invitation-code-sentinel",
		Properties: map[string]string{
			"oauth_GitHub_accessToken":  "oauth-access-token-sentinel",
			"oauth_GitHub_refreshToken": "oauth-refresh-token-sentinel",
		},
	}

	disallowedFields := []string{
		"Password", "PasswordSalt", "PasswordType", "Hash", "PreHash", "AccessToken",
		"OriginalToken", "OriginalRefreshToken", "TotpSecret", "RecoveryCodes",
		"WebauthnCredentials", "FaceIds", "ManagedAccounts", "MfaAccounts", "MfaItems",
		"MfaRememberDeadline", "InvitationCode", "Properties",
		"Properties.oauth_GitHub_accessToken", "Properties.oauth_GitHub_refreshToken",
	}
	attributes := make([]*JwtItem, 0, len(disallowedFields))
	for i, field := range disallowedFields {
		attributes = append(attributes, &JwtItem{
			Name:     "leak" + string(rune('A'+i)),
			Category: "Existing Field",
			Value:    field,
			Type:     "String",
		})
	}

	payload, err := getClaimsCustom(newTokenSecurityTestClaims(user), disallowedFields, attributes)
	if err != nil {
		t.Fatalf("getClaimsCustom returned an unexpected error: %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	for _, sentinel := range []string{
		"password-sentinel", "password-salt-sentinel", "access-token-sentinel",
		"original-token-sentinel", "original-refresh-token-sentinel", "totp-secret-sentinel",
		"recovery-code-sentinel", "managed-password-sentinel", "mfa-account-secret-sentinel",
		"invitation-code-sentinel", "oauth-access-token-sentinel", "oauth-refresh-token-sentinel",
	} {
		if strings.Contains(string(encoded), sentinel) {
			t.Errorf("JWT-Custom contains credential sentinel %q", sentinel)
		}
	}
	for _, item := range attributes {
		if _, ok := payload[item.Name]; ok {
			t.Errorf("JWT-Custom emitted disallowed Existing Field %q", item.Value)
		}
	}
}

func TestJwtCustomAllowsSafeFieldsAndRoleNames(t *testing.T) {
	user := &User{
		Owner: "owner",
		Name:  "alice",
		Id:    "user-id",
		Email: "alice@example.com",
		Roles: []*Role{{Owner: "owner", Name: "admin"}, {Owner: "other", Name: "viewer"}},
		Permissions: []*Permission{
			{Owner: "owner", Name: "read"},
		},
		Groups: []string{"owner/team"},
		Properties: map[string]string{
			"department": "production",
		},
	}
	claims := newTokenSecurityTestClaims(user)

	payload, err := getClaimsCustom(claims,
		[]string{"Email", "Roles", "Permissions", "permissionNames", "Properties.department", "signinMethod", "provider"},
		[]*JwtItem{{Name: "existingRoles", Category: "Existing Field", Value: "Roles", Type: "String"}},
	)
	if err != nil {
		t.Fatalf("getClaimsCustom: %v", err)
	}

	if payload["email"] != "alice@example.com" || payload["department"] != "production" {
		t.Fatalf("safe scalar claims missing: %#v", payload)
	}
	if !reflect.DeepEqual(payload["roles"], []string{"admin", "viewer"}) {
		t.Errorf("Roles must be emitted as names, got %#v", payload["roles"])
	}
	if !reflect.DeepEqual(payload["permissions"], []string{"read"}) {
		t.Errorf("Permissions must be emitted as names, got %#v", payload["permissions"])
	}
	if !reflect.DeepEqual(payload["permissionNames"], []string{"read"}) {
		t.Errorf("permissionNames mismatch: %#v", payload["permissionNames"])
	}
	if !reflect.DeepEqual(payload["existingRoles"], []string{"admin", "viewer"}) {
		t.Errorf("Existing Field Roles mismatch: %#v", payload["existingRoles"])
	}
	if payload["signinMethod"] != "Password" || payload["provider"] != "provider-name" {
		t.Errorf("built-in claims missing: %#v", payload)
	}
}

func TestJwtCustomRejectsReservedClaimOverrides(t *testing.T) {
	reservedNames := []string{
		"iss", "SUB", "Aud", "exp", "nbf", "iat", "jti", "azp", "nonce", "scope",
		"TokenType", "cnf", "client_id", "provider", "SigninMethod", "amr", "acr",
		"AUTH_TIME", "sid",
	}

	for _, name := range reservedNames {
		t.Run(name+"/attribute", func(t *testing.T) {
			_, err := getClaimsCustom(newTokenSecurityTestClaims(&User{Name: "alice"}), nil, []*JwtItem{{
				Name: name, Value: "attacker-controlled", Type: "String", Category: "Static Value",
			}})
			if err == nil || !strings.Contains(err.Error(), "reserved claim") {
				t.Fatalf("expected reserved-claim error for %q, got %v", name, err)
			}
		})

		t.Run(name+"/property", func(t *testing.T) {
			user := &User{Name: "alice", Properties: map[string]string{name: "attacker-controlled"}}
			_, err := getClaimsCustom(newTokenSecurityTestClaims(user), []string{"Properties." + name}, nil)
			if err == nil || !strings.Contains(err.Error(), "reserved claim") {
				t.Fatalf("expected reserved-claim error for property %q, got %v", name, err)
			}
		})
	}
}

func TestRefreshClaimsAreMinimal(t *testing.T) {
	user := &User{
		Owner:         "owner",
		Name:          "alice",
		Email:         "alice@example.com",
		TotpSecret:    "totp-secret-sentinel",
		RecoveryCodes: []string{"recovery-code-sentinel"},
	}
	claims := newTokenSecurityTestClaims(user)
	originalExpiry := claims.ExpiresAt.Time
	refreshExpiry := originalExpiry.Add(24 * time.Hour)
	payload := claimsAsMap(t, getRefreshClaims(claims, refreshExpiry))

	wantKeys := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true,
		"jti": true, "tokenType": true, "scope": true, "azp": true,
	}
	for key := range payload {
		if !wantKeys[key] {
			t.Errorf("refresh token contains non-minimal claim %q", key)
		}
	}
	for key := range wantKeys {
		if _, ok := payload[key]; !ok {
			t.Errorf("refresh token is missing claim %q", key)
		}
	}
	if payload["tokenType"] != "refresh-token" {
		t.Errorf("unexpected tokenType: %v", payload["tokenType"])
	}
	if _, ok := payload["TokenType"]; ok {
		t.Error("refresh token contains the legacy, incorrectly cased TokenType claim")
	}
	if claims.ExpiresAt.Time != originalExpiry {
		t.Error("getRefreshClaims mutated the access-token expiry")
	}
}

func TestRefreshTokenUsesDedicatedParserAndKeyID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := &Cert{
		Name: "rotation-key-2026-07",
		Certificate: string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})),
	}
	now := time.Now().Add(-time.Second)
	refreshClaims := RefreshClaims{
		TokenType: "refresh-token",
		Scope:     "openid profile",
		Azp:       "client-id",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.example.com",
			Subject:   "user-id",
			Audience:  []string{"client-id"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "admin/token-id",
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, newTokenSecurityTestClaims(&User{Id: "user-id"}))
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	setJwtKeyID(cert.Name, accessToken, refreshToken)
	if accessToken.Header["kid"] != cert.Name || refreshToken.Header["kid"] != cert.Name {
		t.Fatalf("kid was not applied to both token types: access=%v refresh=%v", accessToken.Header["kid"], refreshToken.Header["kid"])
	}

	encoded, err := refreshToken.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRefreshJwtToken(encoded, cert)
	if err != nil {
		t.Fatalf("ParseRefreshJwtToken: %v", err)
	}
	if parsed.TokenType != "refresh-token" || parsed.Azp != "client-id" || parsed.ID != "admin/token-id" {
		t.Fatalf("unexpected parsed refresh claims: %#v", parsed)
	}
}

func TestAuthenticationContextAndDPoPClaimsSurviveAllTokenShapes(t *testing.T) {
	claims := newTokenSecurityTestClaims(&User{
		Owner: "owner",
		Name:  "alice",
		Id:    "user-id",
	})
	claims.AuthenticationMethods = []string{"pwd", "otp"}
	claims.AuthTime = 1_700_000_000
	claims.Acr = GetAuthenticationContextClass(claims.AuthenticationMethods)
	claims.Cnf = &DPoPConfirmation{JKT: "test-thumbprint"}

	payloads := map[string]map[string]interface{}{
		"full":     claimsAsMap(t, getClaimsWithoutThirdIdp(claims)),
		"empty":    claimsAsMap(t, getShortClaims(claims)),
		"standard": claimsAsMap(t, getStandardClaims(claims)),
		"refresh":  claimsAsMap(t, getRefreshClaims(claims, time.Unix(1_700_100_000, 0))),
	}
	custom, err := getClaimsCustom(claims, []string{"Email"}, nil)
	if err != nil {
		t.Fatalf("getClaimsCustom: %v", err)
	}
	payloads["custom"] = claimsAsMap(t, custom)

	for name, payload := range payloads {
		t.Run(name, func(t *testing.T) {
			if !reflect.DeepEqual(payload["amr"], []interface{}{"pwd", "otp"}) {
				t.Errorf("amr = %#v", payload["amr"])
			}
			if payload["auth_time"] != float64(claims.AuthTime) {
				t.Errorf("auth_time = %#v", payload["auth_time"])
			}
			if payload["acr"] != AuthenticationContextClassAal2 {
				t.Errorf("acr = %#v", payload["acr"])
			}
			confirmation, ok := payload["cnf"].(map[string]interface{})
			if !ok || confirmation["jkt"] != "test-thumbprint" {
				t.Errorf("cnf = %#v", payload["cnf"])
			}
		})
	}
}
