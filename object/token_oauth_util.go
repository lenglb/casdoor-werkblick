// Copyright 2024 The Casdoor Authors. All Rights Reserved.
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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

const (
	hourSeconds          = int(time.Hour / time.Second)
	InvalidRequest       = "invalid_request"
	InvalidClient        = "invalid_client"
	InvalidGrant         = "invalid_grant"
	UnauthorizedClient   = "unauthorized_client"
	UnsupportedGrantType = "unsupported_grant_type"
	InvalidScope         = "invalid_scope"
	EndpointError        = "endpoint_error"
	DeviceAuthExpiresIn  = 120
	DeviceAuthInterval   = 5

	DeviceAuthStatusPending      = "pending"
	DeviceAuthStatusApproved     = "approved"
	DeviceAuthStatusDenied       = "denied"
	DeviceAuthStatusTokenIssuing = "token_issuing"
	DeviceAuthStatusTokenIssued  = "token_issued"
)

// DeviceAuthMap stores the transient state of the OAuth 2.0 Device Authorization Grant (RFC 8628).
// It defaults to an in-memory store; call InitDeviceAuthStore() at startup to switch to Redis
// when redisEndpoint is configured, enabling correct behaviour across multiple replicas.
var DeviceAuthMap deviceAuthStore = &memoryDeviceAuthStore{}

type Code struct {
	Message string `xorm:"varchar(100)" json:"message"`
	Code    string `xorm:"varchar(100)" json:"code"`
}

type TokenWrapper struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type TokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// DPoPConfirmation holds the DPoP key confirmation claim (RFC 9449).
type DPoPConfirmation struct {
	JKT string `json:"jkt"`
}

type IntrospectionResponse struct {
	Active    bool              `json:"active"`
	Scope     string            `json:"scope,omitempty"`
	ClientId  string            `json:"client_id,omitempty"`
	Username  string            `json:"username,omitempty"`
	TokenType string            `json:"token_type,omitempty"`
	Exp       int64             `json:"exp,omitempty"`
	Iat       int64             `json:"iat,omitempty"`
	Nbf       int64             `json:"nbf,omitempty"`
	Sub       string            `json:"sub,omitempty"`
	Aud       []string          `json:"aud,omitempty"`
	Iss       string            `json:"iss,omitempty"`
	Jti       string            `json:"jti,omitempty"`
	Cnf       *DPoPConfirmation `json:"cnf,omitempty"` // RFC 9449 DPoP key binding
}

type DeviceAuthCache struct {
	UserSignIn            bool
	UserName              string
	ApplicationId         string
	ClientId              string
	Scope                 string
	RequestAt             time.Time
	Status                string
	CancelToken           string
	ExpiresIn             int
	AuthenticationContext AuthenticationContext
}

func InitCleanupDeviceAuthMap() {
	InitDeviceAuthStore()
	InitDPoPReplayStore()
	InitClientAssertionReplayStore()
	util.SafeGoroutine(func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			DeviceAuthMap.Range(func(key, value any) bool {
				cache := value.(DeviceAuthCache)
				expiresIn := cache.ExpiresIn
				if expiresIn == 0 {
					expiresIn = DeviceAuthExpiresIn
				}
				if cache.RequestAt.Add(time.Duration(expiresIn) * time.Second).Before(now) {
					DeviceAuthMap.Delete(key)
				}
				return true
			})
		}
	})
}

type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationUri string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// validateResourceURI validates that the resource parameter is a valid absolute URI
// according to RFC 8707 Section 2
func validateResourceURI(resource string) error {
	if resource == "" {
		return nil // empty resource is allowed (backward compatibility)
	}

	parsedURL, err := url.Parse(resource)
	if err != nil {
		return fmt.Errorf("resource must be a valid URI")
	}

	// RFC 8707: The resource parameter must be an absolute URI
	if !parsedURL.IsAbs() {
		return fmt.Errorf("resource must be an absolute URI")
	}

	return nil
}

// pkceChallenge returns the base64-URL-encoded SHA256 hash of verifier, per RFC 7636
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])
}

var supportedOAuthGrantTypes = map[string]struct{}{
	"authorization_code": {},
	"password":           {},
	"client_credentials": {},
	"token":              {},
	"id_token":           {},
	"refresh_token":      {},
	"urn:ietf:params:oauth:grant-type:jwt-bearer":     {},
	"urn:ietf:params:oauth:grant-type:device_code":    {},
	"urn:ietf:params:oauth:grant-type:token-exchange": {},
}

func IsSupportedOAuthGrantType(grantType string) bool {
	_, ok := supportedOAuthGrantTypes[grantType]
	return ok
}

func ValidateOAuthGrantTypes(grantTypes []string) error {
	seen := make(map[string]struct{}, len(grantTypes))
	for _, grantType := range grantTypes {
		if !IsSupportedOAuthGrantType(grantType) {
			return fmt.Errorf("unsupported OAuth grant type: %q", grantType)
		}
		if _, ok := seen[grantType]; ok {
			return fmt.Errorf("OAuth grant type is duplicated: %q", grantType)
		}
		seen[grantType] = struct{}{}
	}
	return nil
}

func ValidateOAuthNonceForGrant(grantType string, nonce string) *TokenError {
	if grantType == "id_token" && strings.TrimSpace(nonce) == "" {
		return &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "nonce is required for id_token issuance",
		}
	}
	return nil
}

// IsGrantTypeValid checks if grantType is both implemented by the server and
// explicitly allowed in the current application. An empty allowlist rejects
// every grant type.
func IsGrantTypeValid(method string, grantTypes []string) bool {
	if !IsSupportedOAuthGrantType(method) {
		return false
	}
	for _, m := range grantTypes {
		if m == method {
			return true
		}
	}
	return false
}

// isRegexScope returns true if the scope string contains regex metacharacters.
func isRegexScope(scope string) bool {
	return strings.ContainsAny(scope, ".*+?^${}()|[]\\")
}

// IsScopeValidAndExpand expands any regex patterns in the space-separated scope string
// against the application's configured scopes. Literal scopes are kept as-is
// after verifying they exist in the allowed list. Regex scopes are matched
// against every allowed scope name; all matches replace the pattern.
// If the application has no defined scopes, only an empty scope request is
// accepted.
// Returns the expanded scope string and whether the scope is valid.
func IsScopeValidAndExpand(scope string, application *Application) (string, bool) {
	if application == nil {
		return "", false
	}
	if scope == "" {
		return scope, true
	}
	if len(application.Scopes) == 0 {
		return "", false
	}

	allowedNames := make([]string, 0, len(application.Scopes))
	allowedSet := make(map[string]bool, len(application.Scopes))
	for _, s := range application.Scopes {
		if s == nil {
			continue
		}
		allowedNames = append(allowedNames, s.Name)
		allowedSet[s.Name] = true
	}

	seen := make(map[string]bool)
	var expanded []string

	for _, s := range strings.Fields(scope) {
		// Try exact match first.
		if allowedSet[s] {
			if !seen[s] {
				seen[s] = true
				expanded = append(expanded, s)
			}
			continue
		}

		// Not an exact match – if it looks like a regex, try pattern matching.
		if !isRegexScope(s) {
			return "", false
		}

		// Treat as regex pattern – must be a valid regex and match ≥ 1 scope.
		re, err := regexp.Compile("^" + s + "$")
		if err != nil {
			return "", false
		}

		matched := false
		for _, name := range allowedNames {
			if re.MatchString(name) {
				matched = true
				if !seen[name] {
					seen[name] = true
					expanded = append(expanded, name)
				}
			}
		}
		if !matched {
			return "", false
		}
	}

	return strings.Join(expanded, " "), true
}

// IsScopeValid checks whether all space-separated scopes in the scope string
// are defined in the application's Scopes list (including regex expansion).
// If the application has no defined scopes, only an empty scope is valid.
func IsScopeValid(scope string, application *Application) bool {
	_, ok := IsScopeValidAndExpand(scope, application)
	return ok
}

func ValidateDeviceAuthorizationRequest(application *Application, scope string) (string, *TokenError) {
	if application == nil || !IsGrantTypeValid("urn:ietf:params:oauth:grant-type:device_code", application.GrantTypes) {
		return "", &TokenError{
			Error:            UnauthorizedClient,
			ErrorDescription: "device_code grant is not enabled for this application",
		}
	}
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return "", &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "the requested scope is invalid or not defined in the application",
		}
	}
	return expandedScope, nil
}

func ExpireTokenByAccessToken(accessToken string) (bool, *Application, *Token, error) {
	token, err := GetTokenByAccessToken(accessToken)
	if err != nil {
		return false, nil, nil, err
	}
	if token == nil {
		return false, nil, nil, nil
	}

	token.ExpiresIn = 0
	affected, err := ormer.Engine.ID(core.PK{token.Owner, token.Name}).Cols("expires_in").Update(token)
	if err != nil {
		return false, nil, nil, err
	}

	application, err := getApplication(token.Owner, token.Application)
	if err != nil {
		return false, nil, nil, err
	}

	return affected != 0, application, token, nil
}

func CheckOAuthLogin(clientId string, responseType string, redirectUri string, scope string, state string, lang string) (string, *Application, error) {
	requiredGrant, supportedResponseType := requiredGrantForOAuthResponseType(responseType)
	if !supportedResponseType {
		return fmt.Sprintf(i18n.Translate(lang, "token:Grant_type: %s is not supported in this application"), responseType), nil, nil
	}

	application, err := GetApplicationByClientId(clientId)
	if err != nil {
		return "", nil, err
	}

	if application == nil {
		return i18n.Translate(lang, "token:Invalid client_id"), nil, nil
	}
	if !IsGrantTypeValid(requiredGrant, application.GrantTypes) {
		return fmt.Sprintf(i18n.Translate(lang, "token:Grant_type: %s is not supported in this application"), requiredGrant), application, nil
	}

	if !application.IsRedirectUriValid(redirectUri) {
		return fmt.Sprintf(i18n.Translate(lang, "token:Redirect URI: %s doesn't exist in the allowed Redirect URI list"), redirectUri), application, nil
	}

	if !IsScopeValid(scope, application) {
		return i18n.Translate(lang, "token:Invalid scope"), application, nil
	}

	// Mask application for /api/get-app-login
	application.ClientSecret = ""
	return "", application, nil
}

func requiredGrantForOAuthResponseType(responseType string) (string, bool) {
	switch responseType {
	case "code":
		return "authorization_code", true
	case "token", "id_token":
		return responseType, true
	default:
		return "", false
	}
}

// GetOAuthCode is retained for source compatibility with integrations compiled
// against the legacy API. Provider and sign-in labels are not trusted
// authentication evidence, so legacy issuance fails closed. Callers must move
// to GetOAuthCodeWithAuthenticationContext.
// Deprecated: use GetOAuthCodeWithAuthenticationContext.
func GetOAuthCode(userId string, clientId string, provider string, signinMethod string, responseType string, redirectUri string, scope string, state string, nonce string, challenge string, resource string, host string, lang string) (*Code, error) {
	return nil, fmt.Errorf("legacy GetOAuthCode cannot issue tokens without trusted authentication context")
}

func GetOAuthCodeWithAuthenticationContext(userId string, clientId string, authenticationContext AuthenticationContext, responseType string, redirectUri string, scope string, state string, nonce string, challenge string, resource string, host string, lang string) (*Code, error) {
	msg, application, err := CheckOAuthLogin(clientId, responseType, redirectUri, scope, state, lang)
	if err != nil {
		return nil, err
	}
	if msg != "" {
		return &Code{
			Message: msg,
			Code:    "",
		}, nil
	}

	user, err := GetUser(userId)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return &Code{
			Message: fmt.Sprintf("general:The user: %s doesn't exist", userId),
			Code:    "",
		}, nil
	}
	if user.IsForbidden {
		return &Code{
			Message: "error: the user is forbidden to sign in, please contact the administrator",
			Code:    "",
		}, nil
	}

	authenticationContext, err = PreserveAuthenticationContext(authenticationContext)
	if err != nil {
		return nil, fmt.Errorf("invalid authentication context: %w", err)
	}
	if authenticationContext.Subject != user.GetId() {
		return nil, fmt.Errorf("authentication context subject %q does not match user %q", authenticationContext.Subject, user.GetId())
	}

	// Expand regex/wildcard scopes to concrete scope names.
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return &Code{
			Message: i18n.Translate(lang, "token:Invalid scope"),
			Code:    "",
		}, nil
	}
	scope = expandedScope
	user, tokenError, err := revalidateUserTokenAccess(application, user)
	if err != nil {
		return nil, err
	}
	if tokenError != nil {
		return &Code{Message: fmt.Sprintf("error: %s", tokenError.ErrorDescription), Code: ""}, nil
	}
	if tokenError = validateUserTokenAuthenticationPolicy(user, scope, authenticationContext); tokenError != nil {
		return &Code{Message: fmt.Sprintf("error: %s", tokenError.ErrorDescription), Code: ""}, nil
	}

	// Validate resource parameter (RFC 8707)
	if err := validateResourceURI(resource); err != nil {
		return &Code{
			Message: err.Error(),
			Code:    "",
		}, nil
	}

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, err
	}
	accessToken, refreshToken, tokenName, err := generateJwtTokenWithAuthenticationContext(application, user, authenticationContext, nonce, scope, resource, host)
	if err != nil {
		return nil, err
	}

	if challenge == "null" {
		challenge = ""
	}

	token := &Token{
		Owner:         application.Owner,
		Name:          tokenName,
		CreatedTime:   util.GetCurrentTime(),
		Application:   application.Name,
		Organization:  user.Owner,
		User:          user.Name,
		Subject:       user.Id,
		Code:          util.GenerateClientId(),
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		ExpiresIn:     int(application.ExpireInHours * float64(hourSeconds)),
		Scope:         scope,
		Nonce:         nonce,
		TokenType:     "Bearer",
		GrantType:     "authorization_code",
		CodeChallenge: challenge,
		RedirectUri:   redirectUri,
		CodeIsUsed:    false,
		CodeExpireIn:  time.Now().Add(time.Minute * 5).Unix(),
		Resource:      resource,
	}
	if err = token.SetAuthenticationContext(authenticationContext); err != nil {
		return nil, err
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, err
	}

	return &Code{
		Message: "",
		Code:    token.Code,
	}, nil
}

func RefreshToken(application *Application, grantType string, refreshToken string, scope string, clientId string, clientSecret string, host string, dpopProof string, dpopHtus ...string) (interface{}, error) {
	if grantType != "refresh_token" {
		return &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: "grant_type should be refresh_token",
		}, nil
	}

	var err error
	if application == nil {
		application, err = GetApplicationByClientId(clientId)
		if err != nil {
			return nil, err
		}

		if application == nil {
			return &TokenError{
				Error:            InvalidClient,
				ErrorDescription: "client_id is invalid",
			}, nil
		}
	}
	if !IsGrantTypeValid("refresh_token", application.GrantTypes) {
		return &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: "refresh_token is not enabled for this application",
		}, nil
	}

	// check whether the refresh token is valid, and has not expired.
	token, err := GetTokenByRefreshToken(refreshToken)
	if err != nil || token == nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token is invalid or revoked",
		}, nil
	}
	if token.Owner != application.Owner || token.Application != application.Name {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token was not issued to this application",
		}, nil
	}
	if clientId != "" && clientId != application.ClientId {
		return &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_id does not match the refresh token application",
		}, nil
	}
	if application.IsPublicClient() {
		if token.CodeChallenge == "" || clientSecret != "" {
			return &TokenError{
				Error:            InvalidClient,
				ErrorDescription: "public-client refresh requires the original PKCE grant and no client secret",
			}, nil
		}
	} else if subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "confidential client authentication failed",
		}, nil
	}
	if token.RefreshTokenConsumed {
		if err = revokeRefreshTokenFamily(token); err != nil {
			return nil, err
		}
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token reuse detected; the token family has been revoked",
		}, nil
	}

	// check if the token has been invalidated (e.g., by SSO logout)
	if token.ExpiresIn <= 0 {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token is expired",
		}, nil
	}

	cert, err := getCertByApplication(application)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("cert: %s cannot be found", application.Cert),
		}, nil
	}

	oldToken, err := ParseRefreshJwtToken(refreshToken, cert)
	if err != nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("parse refresh token error: %s", err.Error()),
		}, nil
	}
	if oldToken.Azp != application.ClientId {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token authorized party does not match client_id",
		}, nil
	}
	if oldToken.ID != token.GetId() {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token identifier does not match the persisted grant",
		}, nil
	}
	if oldToken.Scope != token.Scope {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token scope does not match the persisted grant",
		}, nil
	}
	if oldToken.Cnf != nil && oldToken.Cnf.JKT != token.DPoPJkt {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token key binding does not match the persisted grant",
		}, nil
	}
	if oldToken.Cnf == nil && token.DPoPJkt != "" {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token is missing its persisted DPoP binding",
		}, nil
	}
	if oldToken.AuthTime != token.AuthTime || !slices.Equal(oldToken.AuthenticationMethods, token.AuthenticationMethods) {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token authentication evidence does not match the persisted grant",
		}, nil
	}
	if token.Subject == "" || oldToken.Subject != token.Subject {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token subject does not match the persisted immutable subject",
		}, nil
	}

	if scope == "" {
		scope = token.Scope
	} else {
		expandedScope, ok := IsScopeValidAndExpand(scope, application)
		if !ok {
			return &TokenError{
				Error:            InvalidScope,
				ErrorDescription: "the requested scope is invalid or not defined in the application",
			}, nil
		}
		originalScopes := map[string]struct{}{}
		for _, originalScope := range strings.Fields(token.Scope) {
			originalScopes[originalScope] = struct{}{}
		}
		for _, requestedScope := range strings.Fields(expandedScope) {
			if _, ok = originalScopes[requestedScope]; !ok {
				return &TokenError{
					Error:            InvalidScope,
					ErrorDescription: fmt.Sprintf("requested scope %q exceeds the original grant", requestedScope),
				}, nil
			}
		}
		scope = expandedScope
	}

	// generate a new token
	user, err := getUser(token.Organization, token.User)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return "", fmt.Errorf("The user: %s doesn't exist", util.GetId(token.Organization, token.User))
	}
	if oldToken.Subject != user.Id || token.Subject != user.Id {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token subject does not match the persisted user",
		}, nil
	}

	user, tokenError, err := revalidateUserTokenAccess(application, user)
	if err != nil {
		return nil, err
	}
	if tokenError != nil {
		return tokenError, nil
	}

	authenticationContext, err := token.GetAuthenticationContext()
	if err != nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("refresh token authentication context is invalid: %s", err.Error()),
		}, nil
	}
	if tokenError = validateUserTokenAuthenticationPolicy(user, scope, authenticationContext); tokenError != nil {
		return tokenError, nil
	}
	if err = ExtendUserWithRolesAndPermissions(user); err != nil {
		return nil, err
	}

	newTokenType := "Bearer"
	newDPoPJkt := ""
	if token.DPoPJkt != "" && dpopProof == "" {
		return &TokenError{
			Error:            "invalid_dpop_proof",
			ErrorDescription: "a DPoP proof is required for this refresh token",
		}, nil
	}
	if dpopProof != "" {
		dpopHtu := GetDPoPHtu(host, "/api/login/oauth/access_token")
		if len(dpopHtus) > 0 && strings.TrimSpace(dpopHtus[0]) != "" {
			dpopHtu = strings.TrimSpace(dpopHtus[0])
		}
		jkt, dpopErr := ValidateDPoPProof(dpopProof, "POST", dpopHtu, "")
		if dpopErr != nil {
			return &TokenError{
				Error:            "invalid_dpop_proof",
				ErrorDescription: dpopErr.Error(),
			}, nil
		}
		if token.DPoPJkt != "" &&
			subtle.ConstantTimeCompare([]byte(token.DPoPJkt), []byte(jkt)) != 1 {
			return &TokenError{
				Error:            "invalid_dpop_proof",
				ErrorDescription: "DPoP proof key does not match the refresh token binding",
			}, nil
		}
		newTokenType = "DPoP"
		newDPoPJkt = jkt
	}

	newAccessToken, newRefreshToken, tokenName, err := generateJwtTokenWithAuthenticationContextAndDPoP(application, user, authenticationContext, newDPoPJkt, "", scope, token.Resource, host)
	if err != nil {
		return &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}
	if token.RefreshTokenFamily == "" {
		token.RefreshTokenFamily = token.GetId()
	}

	newToken := &Token{
		Owner:              application.Owner,
		Name:               tokenName,
		CreatedTime:        util.GetCurrentTime(),
		Application:        application.Name,
		Organization:       user.Owner,
		User:               user.Name,
		Subject:            user.Id,
		Code:               util.GenerateClientId(),
		AccessToken:        newAccessToken,
		RefreshToken:       newRefreshToken,
		ExpiresIn:          int(application.ExpireInHours * float64(hourSeconds)),
		Scope:              scope,
		TokenType:          newTokenType,
		GrantType:          "refresh_token",
		CodeChallenge:      token.CodeChallenge,
		RedirectUri:        token.RedirectUri,
		Resource:           token.Resource,
		DPoPJkt:            newDPoPJkt,
		RefreshTokenFamily: token.RefreshTokenFamily,
	}
	if err = newToken.SetAuthenticationContext(authenticationContext); err != nil {
		return nil, err
	}

	rotated, err := rotateRefreshToken(token, newToken)
	if err != nil {
		return nil, err
	}
	if !rotated {
		if revokeErr := revokeRefreshTokenFamily(token); revokeErr != nil {
			return nil, revokeErr
		}
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "refresh token reuse detected; the token family has been revoked",
		}, nil
	}

	tokenWrapper := &TokenWrapper{
		AccessToken:  newToken.AccessToken,
		IdToken:      newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		TokenType:    newToken.TokenType,
		ExpiresIn:    newToken.ExpiresIn,
		Scope:        newToken.Scope,
	}
	return tokenWrapper, nil
}

const (
	clientAssertionMaxLifetime = 5 * time.Minute
	clientAssertionFutureSkew  = 30 * time.Second
	clientAssertionMaxJtiBytes = 256
)

func ValidateJwtAssertion(clientAssertion string, application *Application, host string) (bool, *Claims, error) {
	_, originBackend := getOriginFromHost(host)

	clientCert, err := getCert(application.Owner, application.ClientCert)
	if err != nil {
		return false, nil, err
	}
	if clientCert == nil {
		return false, nil, fmt.Errorf("client certificate is not configured for application: [%s]", application.GetId())
	}

	claims, err := ParseJwtToken(clientAssertion, clientCert)
	if err != nil {
		return false, nil, err
	}

	if err = validateClientAssertionClaims(application, claims, originBackend, time.Now(), true); err != nil {
		return false, claims, err
	}

	return true, claims, nil
}

func validateClientAssertionClaims(application *Application, claims *Claims, originBackend string, now time.Time, consumeReplay bool) error {
	if application == nil || claims == nil {
		return fmt.Errorf("client assertion claims are invalid")
	}
	if claims.Subject != application.ClientId || claims.Issuer != application.ClientId {
		return fmt.Errorf("client assertion iss and sub must equal client_id")
	}

	expectedAudience := fmt.Sprintf("%s/api/login/oauth/access_token", strings.TrimRight(originBackend, "/"))
	if len(claims.Audience) != 1 || claims.Audience[0] != expectedAudience {
		return fmt.Errorf("client assertion aud must exactly match the token endpoint")
	}
	if claims.ExpiresAt == nil {
		return fmt.Errorf("client assertion missing exp claim")
	}
	if claims.IssuedAt == nil {
		return fmt.Errorf("client assertion missing iat claim")
	}
	if claims.ID == "" || strings.TrimSpace(claims.ID) == "" {
		return fmt.Errorf("client assertion missing jti claim")
	}
	if len(claims.ID) > clientAssertionMaxJtiBytes {
		return fmt.Errorf("client assertion jti is too long")
	}

	issuedAt := claims.IssuedAt.Time
	expiresAt := claims.ExpiresAt.Time
	if issuedAt.After(now.Add(clientAssertionFutureSkew)) {
		return fmt.Errorf("client assertion iat is too far in the future")
	}
	if issuedAt.Before(now.Add(-clientAssertionMaxLifetime)) {
		return fmt.Errorf("client assertion iat is outside the acceptable time window")
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("client assertion has expired")
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > clientAssertionMaxLifetime {
		return fmt.Errorf("client assertion lifetime must be at most %s", clientAssertionMaxLifetime)
	}

	if consumeReplay {
		replayKeyInput := strings.Join([]string{application.ClientId, claims.ID}, "\x00")
		replayKeyHash := sha256.Sum256([]byte(replayKeyInput))
		replayKey := base64.RawURLEncoding.EncodeToString(replayKeyHash[:])
		if err := useClientAssertionOnce(replayKey, expiresAt.Sub(now)); err != nil {
			return err
		}
	}

	return nil
}

func ValidateClientAssertionForApplication(clientAssertion string, application *Application, host string) (bool, error) {
	if application == nil || application.GetTokenEndpointAuthMethod() != ClientAuthMethodPrivateKeyJwt {
		return false, nil
	}
	ok, _, err := ValidateJwtAssertion(clientAssertion, application, host)
	return ok, err
}

func ValidateClientAssertion(clientAssertion string, host string) (bool, *Application, error) {
	token, err := ParseJwtTokenWithoutValidation(clientAssertion)
	if err != nil {
		return false, nil, err
	}

	clientId, err := token.Claims.GetSubject()
	if err != nil {
		return false, nil, err
	}

	application, err := GetApplicationByClientId(clientId)
	if err != nil {
		return false, nil, err
	}
	if application == nil {
		return false, nil, fmt.Errorf("application not found for client: [%s]", clientId)
	}
	if application.GetTokenEndpointAuthMethod() != ClientAuthMethodPrivateKeyJwt {
		return false, application, nil
	}

	ok, err := ValidateClientAssertionForApplication(clientAssertion, application, host)
	if err != nil {
		return false, application, err
	}
	if !ok {
		return false, application, nil
	}

	return true, application, nil
}

// mintImplicitToken mints a token for an already-authenticated user.
// Callers must verify user identity before calling this function.
func mintImplicitToken(application *Application, username string, scope string, nonce string, host string) (*Token, *TokenError, error) {
	return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "trusted authentication context is required"}, nil
}

func mintImplicitTokenWithAuthenticationContext(application *Application, username string, requiredGrant string, scope string, nonce string, host string, authenticationContext *AuthenticationContext) (*Token, *TokenError, error) {
	if application == nil || !IsGrantTypeValid(requiredGrant, application.GrantTypes) {
		return nil, &TokenError{Error: UnsupportedGrantType, ErrorDescription: fmt.Sprintf("%s is not enabled for this application", requiredGrant)}, nil
	}
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return nil, &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "the requested scope is invalid or not defined in the application",
		}, nil
	}
	scope = expandedScope

	user, err := GetUserByFieldsForSharedApp(application, application.Organization, username)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "the user does not exist",
		}, nil
	}

	user, tokenError, err := revalidateUserTokenAccess(application, user)
	if err != nil || tokenError != nil {
		return nil, tokenError, err
	}

	if authenticationContext == nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "trusted authentication context is required"}, nil
	}
	token, err := GetTokenByUserForGrantWithAuthenticationContext(application, user, requiredGrant, scope, nonce, host, *authenticationContext)
	if err != nil {
		return nil, nil, err
	}
	return token, nil, nil
}

type validatedSubjectToken struct {
	Owner                 string
	Name                  string
	Subject               string
	Scope                 string
	AuthenticationContext AuthenticationContext
	DPoPJkt               string
}

// parseAndValidateSubjectToken validates a subject_token for RFC 8693 token
// exchange. The persisted access-token record is the revocation and token-type
// boundary; unverified JWT claims are never used to select an application.
func parseAndValidateSubjectToken(subjectToken string, requestingClientId string, proofJkt string) (*validatedSubjectToken, *TokenError, error) {
	record, err := GetTokenByAccessToken(subjectToken)
	if err != nil {
		return nil, nil, err
	}
	if record == nil || record.ExpiresIn <= 0 || !record.CodeIsUsed {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "subject_token is not an active access token"}, nil
	}

	issuingApp, err := GetApplication(util.GetId(record.Owner, record.Application))
	if err != nil {
		return nil, nil, err
	}
	if issuingApp == nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "subject_token issuing application does not exist"}, nil
	}
	cert, err := getCertByApplication(issuingApp)
	if err != nil {
		return nil, nil, err
	}
	if cert == nil {
		return nil, &TokenError{Error: EndpointError, ErrorDescription: "subject_token issuing certificate does not exist"}, nil
	}

	var tokenType, azp, signedScope, subject string
	var audience []string
	var confirmation *DPoPConfirmation
	if issuingApp.TokenFormat == "JWT-Standard" {
		claims, parseErr := ParseStandardJwtToken(subjectToken, cert)
		if parseErr != nil {
			return nil, &TokenError{Error: InvalidGrant, ErrorDescription: fmt.Sprintf("invalid subject_token: %s", parseErr.Error())}, nil
		}
		tokenType, azp, signedScope, subject = claims.TokenType, claims.Azp, claims.Scope, claims.Subject
		audience, confirmation = claims.Audience, claims.Cnf
	} else {
		claims, parseErr := ParseJwtToken(subjectToken, cert)
		if parseErr != nil {
			return nil, &TokenError{Error: InvalidGrant, ErrorDescription: fmt.Sprintf("invalid subject_token: %s", parseErr.Error())}, nil
		}
		tokenType, azp, signedScope, subject = claims.TokenType, claims.Azp, claims.Scope, claims.Subject
		audience, confirmation = claims.Audience, claims.Cnf
	}

	if tokenType != "access-token" {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "subject_token is not an access token"}, nil
	}
	if record.Subject == "" || subject != record.Subject {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "subject_token subject does not match the persisted immutable subject"}, nil
	}
	if azp != issuingApp.ClientId || signedScope != record.Scope {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "subject_token claims do not match the persisted grant"}, nil
	}
	if !DPoPConfirmationMatches(confirmation, record.DPoPJkt) {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "subject_token key binding does not match the persisted grant"}, nil
	}
	if issuingApp.ClientId != requestingClientId && !slices.Contains(audience, requestingClientId) {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: fmt.Sprintf("subject_token audience does not include the requesting client %q", requestingClientId)}, nil
	}
	if record.DPoPJkt != "" {
		if proofJkt == "" || subtle.ConstantTimeCompare([]byte(record.DPoPJkt), []byte(proofJkt)) != 1 {
			return nil, &TokenError{Error: "invalid_dpop_proof", ErrorDescription: "proof key does not match the DPoP-bound subject_token"}, nil
		}
	}

	authenticationContext, err := record.GetAuthenticationContext()
	if err != nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: fmt.Sprintf("subject_token authentication context is invalid: %s", err.Error())}, nil
	}
	return &validatedSubjectToken{
		Owner:                 record.Organization,
		Name:                  record.User,
		Subject:               subject,
		Scope:                 record.Scope,
		AuthenticationContext: authenticationContext,
		DPoPJkt:               record.DPoPJkt,
	}, nil, nil
}

// createGuestUserToken creates a new guest user and returns a token for them.
func createGuestUserToken(application *Application, clientSecret string, verifier string, hosts ...string) (*Token, *TokenError, error) {
	if clientSecret == "" ||
		subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "guest-user authorization requires a valid client_secret",
		}, nil
	}

	guestUsername := generateGuestUsername()
	guestPassword := util.GenerateId()

	organization, err := GetOrganization(util.GetId("admin", application.Organization))
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to get organization: %s", err.Error()),
		}, nil
	}
	if organization == nil {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: fmt.Sprintf("organization: %s does not exist", application.Organization),
		}, nil
	}

	initScore, err := organization.GetInitScore()
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to get init score: %s", err.Error()),
		}, nil
	}

	newUserId, idErr := GenerateIdForNewUser(application)
	if idErr != nil {
		newUserId = util.GenerateId()
	}

	guestUser := &User{
		Owner:             application.Organization,
		Name:              guestUsername,
		CreatedTime:       util.GetCurrentTime(),
		Id:                newUserId,
		Type:              "normal-user",
		Password:          guestPassword,
		Tag:               "guest-user",
		DisplayName:       fmt.Sprintf("Guest_%s", guestUsername[:8]),
		Avatar:            "",
		Address:           []string{},
		Email:             "",
		Phone:             "",
		Score:             initScore,
		IsAdmin:           false,
		IsForbidden:       false,
		IsDeleted:         false,
		SignupApplication: application.Name,
		Properties:        map[string]string{},
		RegisterType:      "Guest Signup",
		RegisterSource:    fmt.Sprintf("%s/%s", application.Organization, application.Name),
	}

	affected, err := AddUser(guestUser, "en")
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to create guest user: %s", err.Error()),
		}, nil
	}
	if !affected {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: "failed to create guest user",
		}, nil
	}

	err = ExtendUserWithRolesAndPermissions(guestUser)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to extend user: %s", err.Error()),
		}, nil
	}

	authenticationContext, err := PreserveAuthenticationContext(AuthenticationContext{
		Subject:  guestUser.GetId(),
		AuthTime: time.Now().Unix(),
		Amr:      []string{"guest"},
	})
	if err != nil {
		return nil, nil, err
	}
	host := ""
	if len(hosts) > 0 {
		host = hosts[0]
	}
	accessToken, refreshToken, tokenName, err := generateJwtTokenWithAuthenticationContext(application, guestUser, authenticationContext, "", "", "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to generate token: %s", err.Error()),
		}, nil
	}

	token := &Token{
		Owner:         application.Owner,
		Name:          tokenName,
		CreatedTime:   util.GetCurrentTime(),
		Application:   application.Name,
		Organization:  guestUser.Owner,
		User:          guestUser.Name,
		Subject:       guestUser.Id,
		Code:          util.GenerateClientId(),
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		ExpiresIn:     int(application.ExpireInHours * float64(hourSeconds)),
		Scope:         "",
		TokenType:     "Bearer",
		GrantType:     "authorization_code",
		CodeChallenge: "",
		CodeIsUsed:    true,
		CodeExpireIn:  0,
	}
	if err = token.SetAuthenticationContext(authenticationContext); err != nil {
		return nil, nil, err
	}

	_, err = AddToken(token)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("failed to add token: %s", err.Error()),
		}, nil
	}

	return token, nil, nil
}

// generateGuestUsername generates a unique username for guest users.
func generateGuestUsername() string {
	return fmt.Sprintf("guest_%s", util.GenerateUUID())
}
