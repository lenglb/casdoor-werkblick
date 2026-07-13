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
	"crypto/subtle"
	"fmt"
	"strings"
	"time"

	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/util"
)

func GetOAuthToken(grantType string, clientId string, clientSecret string, code string, verifier string, scope string, nonce string, username string, password string, host string, refreshToken string, tag string, avatar string, lang string, subjectToken string, subjectTokenType string, assertion string, clientAssertion string, clientAssertionType string, audience string, resource string, deviceCode string, dpopProof string, clientAuthentication *OAuthClientAuthentication, authenticationContexts ...*AuthenticationContext) (interface{}, error) {
	return getOAuthToken(grantType, clientId, clientSecret, code, verifier, "", scope, nonce, username, password, host, refreshToken, tag, avatar, lang, subjectToken, subjectTokenType, assertion, clientAssertion, clientAssertionType, audience, resource, deviceCode, dpopProof, clientAuthentication, authenticationContexts...)
}

// GetOAuthTokenWithRedirectUri binds authorization-code redemption to the
// exact redirect URI from the authorization request. The legacy entry point is
// retained for source compatibility, but cannot redeem newly issued codes
// because those always carry a non-empty redirect URI binding.
func GetOAuthTokenWithRedirectUri(grantType string, clientId string, clientSecret string, code string, verifier string, redirectUri string, scope string, nonce string, username string, password string, host string, refreshToken string, tag string, avatar string, lang string, subjectToken string, subjectTokenType string, assertion string, clientAssertion string, clientAssertionType string, audience string, resource string, deviceCode string, dpopProof string, clientAuthentication *OAuthClientAuthentication, authenticationContexts ...*AuthenticationContext) (interface{}, error) {
	return getOAuthToken(grantType, clientId, clientSecret, code, verifier, redirectUri, scope, nonce, username, password, host, refreshToken, tag, avatar, lang, subjectToken, subjectTokenType, assertion, clientAssertion, clientAssertionType, audience, resource, deviceCode, dpopProof, clientAuthentication, authenticationContexts...)
}

func getOAuthToken(grantType string, clientId string, clientSecret string, code string, verifier string, redirectUri string, scope string, nonce string, username string, password string, host string, refreshToken string, tag string, avatar string, lang string, subjectToken string, subjectTokenType string, assertion string, clientAssertion string, clientAssertionType string, audience string, resource string, deviceCode string, dpopProof string, clientAuthentication *OAuthClientAuthentication, authenticationContexts ...*AuthenticationContext) (interface{}, error) {
	var authenticationContext *AuthenticationContext
	if len(authenticationContexts) > 0 {
		authenticationContext = authenticationContexts[0]
	}

	application, authenticationError, err := AuthenticateOAuthClient(clientAuthentication, host)
	if err != nil {
		return nil, err
	}
	if authenticationError != nil {
		return authenticationError, nil
	}
	clientId = application.ClientId
	clientSecret = clientAuthentication.EffectiveClientSecret(application)

	// Handle WeChat Mini Program flow separately — it does not use standard OAuth grant types
	if tag == "wechat_miniprogram" {
		if dpopProof != "" {
			return &TokenError{Error: "invalid_dpop_proof", ErrorDescription: "WeChat Mini Program flow does not support DPoP"}, nil
		}
		if application.IsPublicClient() || subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
			return &TokenError{Error: InvalidClient, ErrorDescription: "WeChat Mini Program flow requires confidential client authentication"}, nil
		}
		token, tokenError, err := GetWechatMiniProgramToken(application, code, host, username, avatar, lang)
		if err != nil {
			return nil, err
		}
		if tokenError != nil {
			return tokenError, nil
		}
		return &TokenWrapper{
			AccessToken:  token.AccessToken,
			IdToken:      token.AccessToken,
			RefreshToken: token.RefreshToken,
			TokenType:    token.TokenType,
			ExpiresIn:    token.ExpiresIn,
			Scope:        token.Scope,
		}, nil
	}

	// Check if grantType is allowed in the current application
	if !IsGrantTypeValid(grantType, application.GrantTypes) {
		return &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("grant_type: %s is not supported in this application", grantType),
		}, nil
	}
	if nonceError := ValidateOAuthNonceForGrant(grantType, nonce); nonceError != nil {
		return nonceError, nil
	}
	if application.IsPublicClient() {
		switch grantType {
		case "client_credentials", "password", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:token-exchange":
			return &TokenError{
				Error:            UnauthorizedClient,
				ErrorDescription: "this grant type requires a confidential client",
			}, nil
		}
	}
	switch grantType {
	case "password", "token", "id_token", "urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:device_code":
		if application.IsPublicClient() {
			if clientSecret != "" {
				return &TokenError{Error: InvalidClient, ErrorDescription: "public clients must not send a client secret"}, nil
			}
		} else if subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
			return &TokenError{Error: InvalidClient, ErrorDescription: "confidential client authentication failed"}, nil
		}
	}

	var token *Token
	var tokenError *TokenError
	var claimedDeviceAuth *DeviceAuthCache
	var dpopJkt string
	if dpopProof != "" && grantType != "refresh_token" {
		dpopHtu := GetDPoPHtu(host, "/api/login/oauth/access_token")
		dpopJkt, err = ValidateDPoPProof(dpopProof, "POST", dpopHtu, "")
		if err != nil {
			return &TokenError{
				Error:            "invalid_dpop_proof",
				ErrorDescription: err.Error(),
			}, nil
		}
	}

	switch grantType {
	case "authorization_code": // Authorization Code Grant
		token, tokenError, err = getAuthorizationCodeToken(application, clientSecret, code, verifier, redirectUri, resource, host, dpopJkt)
	case "password": // Resource Owner Password Credentials Grant
		token, tokenError, err = GetPasswordToken(application, username, password, scope, host)
	case "client_credentials": // Client Credentials Grant
		token, tokenError, err = GetClientCredentialsToken(application, clientSecret, scope, host)
	case "token", "id_token": // Implicit Grant
		token, tokenError, err = getImplicitTokenForGrant(application, username, password, grantType, scope, nonce, host)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		token, tokenError, err = GetJwtBearerToken(application, assertion, scope, nonce, host)
	case "urn:ietf:params:oauth:grant-type:device_code":
		claimed, claimResult := ClaimDeviceAuthTokenIssuance(deviceCode, application.GetId(), application.ClientId, time.Now())
		if claimResult != DeviceAuthTokenClaimed {
			tokenError = deviceAuthTokenClaimError(claimResult)
			break
		}
		claimedDeviceAuth = &claimed
		username = claimed.UserName
		scope = claimed.Scope
		authenticationContext = &claimed.AuthenticationContext
		// The user has already authenticated via browser in the device flow.
		// The atomic claim above is the single-use boundary, so only this
		// request may mint the resulting token family.
		token, tokenError, err = mintImplicitTokenWithAuthenticationContext(application, username, grantType, scope, nonce, host, authenticationContext)
	case "urn:ietf:params:oauth:grant-type:token-exchange": // Token Exchange Grant (RFC 8693)
		token, tokenError, err = GetTokenExchangeToken(application, clientSecret, subjectToken, subjectTokenType, audience, scope, host, dpopJkt)
	case "refresh_token":
		refreshToken2, err := RefreshToken(application, grantType, refreshToken, scope, clientId, clientSecret, host, dpopProof)
		if err != nil {
			return nil, err
		}
		return refreshToken2, nil
	default:
		return &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("grant_type: %s is not implemented by this server", grantType),
		}, nil
	}

	if err != nil {
		abortDeviceAuthTokenIssuance(deviceCode, claimedDeviceAuth, token)
		return nil, err
	}

	if tokenError != nil {
		abortDeviceAuthTokenIssuance(deviceCode, claimedDeviceAuth, token)
		return tokenError, nil
	}
	if token == nil {
		abortDeviceAuthTokenIssuance(deviceCode, claimedDeviceAuth, token)
		return &TokenError{
			Error:            EndpointError,
			ErrorDescription: "OAuth grant completed without issuing a token",
		}, nil
	}

	// Authorization-code DPoP binding is persisted atomically with code
	// consumption. Token exchange mints its output with cnf directly. Other
	// grants replace the just-issued signed credentials and DB marker together.
	if dpopJkt != "" && grantType != "authorization_code" && grantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		tokenError, err = bindIssuedTokenToDPoPWithCleanup(application, token, dpopJkt, host, deviceCode, claimedDeviceAuth)
		if err != nil {
			return nil, err
		}
		if tokenError != nil {
			return tokenError, nil
		}
	}

	if claimedDeviceAuth != nil && !CompleteDeviceAuthTokenIssuance(deviceCode, claimedDeviceAuth.ApplicationId, claimedDeviceAuth.ClientId) {
		abortDeviceAuthTokenIssuance(deviceCode, claimedDeviceAuth, token)
		return &TokenError{
			Error:            EndpointError,
			ErrorDescription: "device authorization could not be finalized",
		}, nil
	}

	tokenWrapper := &TokenWrapper{
		AccessToken:  token.AccessToken,
		IdToken:      token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.ExpiresIn,
		Scope:        token.Scope,
	}

	return tokenWrapper, nil
}

func deviceAuthTokenClaimError(result DeviceAuthTokenClaimResult) *TokenError {
	switch result {
	case DeviceAuthTokenNotFound, DeviceAuthTokenExpired:
		return &TokenError{Error: "expired_token", ErrorDescription: "device_code is expired or invalid"}
	case DeviceAuthTokenPending, DeviceAuthTokenIssuanceInProgress:
		return &TokenError{Error: "authorization_pending", ErrorDescription: "device authorization is pending"}
	case DeviceAuthTokenDenied:
		return &TokenError{Error: "access_denied", ErrorDescription: "device authorization was denied"}
	case DeviceAuthTokenAlreadyIssued:
		return &TokenError{Error: "access_denied", ErrorDescription: "device_code has already been used"}
	case DeviceAuthTokenBindingMismatch:
		return &TokenError{Error: InvalidGrant, ErrorDescription: "device_code was not issued to this client"}
	default:
		return &TokenError{Error: InvalidGrant, ErrorDescription: "device_code state is invalid"}
	}
}

func deleteIssuedTokenForFailedIssuance(token *Token) error {
	if token == nil {
		return fmt.Errorf("issued token is missing")
	}
	deleted, err := DeleteToken(token)
	if err != nil {
		return err
	}
	if !deleted {
		return fmt.Errorf("issued token no longer matches a persisted row")
	}
	return nil
}

// abortDeviceAuthTokenIssuance rolls an exclusive claim back only when no
// usable token row remains. If cleanup of an already-minted row fails, the
// status deliberately stays token_issuing so a retry cannot create a second
// token family.
func abortDeviceAuthTokenIssuance(deviceCode string, claimed *DeviceAuthCache, token *Token) error {
	if claimed == nil {
		return nil
	}
	if token != nil {
		if err := deleteIssuedTokenForFailedIssuance(token); err != nil {
			return err
		}
	}
	if !RollbackDeviceAuthTokenIssuance(deviceCode, claimed.ApplicationId, claimed.ClientId) {
		return fmt.Errorf("device authorization issuance could not be rolled back")
	}
	return nil
}

func cleanupFailedPostMintDPoPBinding(deviceCode string, claimed *DeviceAuthCache, token *Token) error {
	if claimed != nil {
		return abortDeviceAuthTokenIssuance(deviceCode, claimed, token)
	}
	return deleteIssuedTokenForFailedIssuance(token)
}

func bindIssuedTokenToDPoPWithCleanup(application *Application, token *Token, dpopJkt string, host string, deviceCode string, claimed *DeviceAuthCache) (*TokenError, error) {
	tokenError, err := bindIssuedTokenToDPoP(application, token, dpopJkt, host)
	if err == nil && tokenError == nil {
		return nil, nil
	}

	cleanupErr := cleanupFailedPostMintDPoPBinding(deviceCode, claimed, token)
	if cleanupErr != nil {
		if err != nil {
			return nil, fmt.Errorf("DPoP binding failed: %v; issued bearer token cleanup failed: %w", err, cleanupErr)
		}
		return nil, fmt.Errorf("DPoP binding was rejected: %s; issued bearer token cleanup failed: %w", tokenError.ErrorDescription, cleanupErr)
	}
	return tokenError, err
}

func bindIssuedTokenToDPoP(application *Application, token *Token, dpopJkt string, host string) (*TokenError, error) {
	if token == nil || dpopJkt == "" {
		return nil, nil
	}
	if tokenError := validateIssuedTokenDPoPBinding(application, token); tokenError != nil {
		return tokenError, nil
	}

	var accessToken, refreshToken string
	var err error
	if token.GrantType == "client_credentials" {
		nullUser := &User{
			Owner: application.Owner,
			Id:    application.GetId(),
			Name:  application.Name,
			Type:  "application",
		}
		accessToken, refreshToken, _, err = generateJwtTokenInternal(
			application, nullUser, "", "", nil, dpopJkt, token.Nonce, token.Scope, token.Resource, host, token.Name,
		)
	} else {
		user, authenticationContext, tokenError, userErr := revalidateIssuedUserTokenForDPoP(application, token)
		if userErr != nil || tokenError != nil {
			return tokenError, userErr
		}
		if userErr = ExtendUserWithRolesAndPermissions(user); userErr != nil {
			return nil, userErr
		}
		accessToken, refreshToken, _, err = generateJwtTokenWithAuthenticationContextAndDPoP(
			application, user, authenticationContext, dpopJkt, token.Nonce, token.Scope, token.Resource, host, token.Name,
		)
	}
	if err != nil {
		return nil, err
	}
	if token.RefreshToken == "" {
		refreshToken = ""
	}

	replaced, err := replaceIssuedTokenWithDPoP(token, accessToken, refreshToken, dpopJkt)
	if err != nil {
		return nil, err
	}
	if !replaced {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "issued token changed before DPoP binding completed"}, nil
	}
	token.AccessToken = accessToken
	token.RefreshToken = refreshToken
	token.AccessTokenHash = getTokenHash(accessToken)
	token.RefreshTokenHash = getTokenHash(refreshToken)
	token.TokenType = "DPoP"
	token.DPoPJkt = dpopJkt
	return nil, nil
}

func validateIssuedTokenDPoPBinding(application *Application, token *Token) *TokenError {
	if application == nil || token == nil {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "issued token cannot be bound without its application"}
	}
	if token.Owner != application.Owner || token.Application != application.Name {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "issued token does not belong to the authenticated application"}
	}
	if token.GrantType == "" || !IsGrantTypeValid(token.GrantType, application.GrantTypes) {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "issued token grant is no longer enabled for the application"}
	}
	if token.GrantType == "client_credentials" &&
		(token.Subject != application.GetId() || token.User != application.Name || token.Organization != application.Organization) {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "issued client credentials token does not identify the authenticated application"}
	}
	return nil
}

// revalidateIssuedUserTokenForDPoP treats DPoP binding as a new user-token
// minting boundary. The persisted immutable subject, current durable access
// policy, and current MFA assurance must all still match before replacement.
func revalidateIssuedUserTokenForDPoP(application *Application, token *Token) (*User, AuthenticationContext, *TokenError, error) {
	if token == nil || token.Subject == "" {
		return nil, AuthenticationContext{}, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "issued token has no immutable subject binding",
		}, nil
	}

	user, tokenError, err := revalidateUserTokenAccess(application, &User{
		Owner: token.Organization,
		Name:  token.User,
		Id:    token.Subject,
	})
	if err != nil || tokenError != nil {
		return nil, AuthenticationContext{}, tokenError, err
	}

	authenticationContext, contextErr := token.GetAuthenticationContext()
	if contextErr != nil {
		return nil, AuthenticationContext{}, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("issued token authentication context is invalid: %s", contextErr.Error()),
		}, nil
	}
	if tokenError = validateUserTokenAuthenticationPolicy(user, token.Scope, authenticationContext); tokenError != nil {
		return nil, AuthenticationContext{}, tokenError, nil
	}

	return user, authenticationContext, nil, nil
}

// GetAuthorizationCodeToken handles the Authorization Code Grant flow.
func GetAuthorizationCodeToken(application *Application, clientSecret string, code string, verifier string, resource string) (*Token, *TokenError, error) {
	return getAuthorizationCodeToken(application, clientSecret, code, verifier, "", resource, "", "")
}

func GetAuthorizationCodeTokenForHost(application *Application, clientSecret string, code string, verifier string, resource string, host string) (*Token, *TokenError, error) {
	return getAuthorizationCodeToken(application, clientSecret, code, verifier, "", resource, host, "")
}

func GetAuthorizationCodeTokenWithRedirectUri(application *Application, clientSecret string, code string, verifier string, redirectUri string, resource string) (*Token, *TokenError, error) {
	return getAuthorizationCodeToken(application, clientSecret, code, verifier, redirectUri, resource, "", "")
}

func GetAuthorizationCodeTokenForHostAndRedirectUri(application *Application, clientSecret string, code string, verifier string, redirectUri string, resource string, host string) (*Token, *TokenError, error) {
	return getAuthorizationCodeToken(application, clientSecret, code, verifier, redirectUri, resource, host, "")
}

func getAuthorizationCodeToken(application *Application, clientSecret string, code string, verifier string, redirectUri string, resource string, host string, dpopJkt string) (*Token, *TokenError, error) {
	if application == nil || !IsGrantTypeValid("authorization_code", application.GrantTypes) {
		return nil, &TokenError{
			Error:            UnsupportedGrantType,
			ErrorDescription: "authorization_code is not enabled for this application",
		}, nil
	}
	if code == "" {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "authorization code should not be empty",
		}, nil
	}

	// Handle guest user creation
	if code == "guest-user" {
		if dpopJkt != "" {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "guest-user authorization does not support DPoP",
			}, nil
		}
		if application.Organization == "built-in" {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "guest signin is not allowed for built-in organization",
			}, nil
		}
		if !application.EnableGuestSignin {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "guest signin is not enabled for this application",
			}, nil
		}
		if !application.EnableSignUp {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "sign up is not enabled for this application",
			}, nil
		}
		if !isExactRegisteredRedirectUri(application, redirectUri) {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "guest-user authorization requires an exact registered redirect_uri",
			}, nil
		}
		return createGuestUserToken(application, clientSecret, verifier, redirectUri, host)
	}

	token, err := getTokenByCode(code)
	if err != nil {
		return nil, nil, err
	}

	if token == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code: [%s] is invalid", code),
		}, nil
	}

	if token.CodeIsUsed {
		// anti replay attacks
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code has been used for token: [%s]", token.GetId()),
		}, nil
	}
	if token.GrantType != "authorization_code" {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "authorization code grant binding is missing or invalid",
		}, nil
	}

	if token.CodeChallenge != "" {
		challengeAnswer := pkceChallenge(verifier)
		if challengeAnswer != token.CodeChallenge {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: fmt.Sprintf("verifier is invalid, challengeAnswer: [%s], token.CodeChallenge: [%s]", challengeAnswer, token.CodeChallenge),
			}, nil
		}
	}

	if application.IsPublicClient() {
		if token.CodeChallenge == "" || clientSecret != "" {
			return nil, &TokenError{
				Error:            InvalidClient,
				ErrorDescription: "public clients must use PKCE and must not authenticate with a client secret",
			}, nil
		}
	} else if subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "confidential client authentication failed",
		}, nil
	}

	if application.Owner != token.Owner || application.Name != token.Application {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "authorization code was not issued to this application",
		}, nil
	}
	if token.RedirectUri == "" || redirectUri == "" || redirectUri != token.RedirectUri {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "redirect_uri does not match the authorization request",
		}, nil
	}

	// RFC 8707: Validate resource parameter matches the one in the authorization request
	if resource != token.Resource {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("resource parameter does not match authorization request, expected: [%s], got: [%s]", token.Resource, resource),
		}, nil
	}

	nowUnix := time.Now().Unix()
	if nowUnix > token.CodeExpireIn {
		// code must be used within 5 minutes
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code has expired, nowUnix: [%s], token.CodeExpireIn: [%s]", time.Unix(nowUnix, 0).Format(time.RFC3339), time.Unix(token.CodeExpireIn, 0).Format(time.RFC3339)),
		}, nil
	}

	if token.Subject == "" {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "authorization code has no immutable subject binding"}, nil
	}
	user, accessError, userErr := revalidateUserTokenAccess(application, &User{Owner: token.Organization, Name: token.User, Id: token.Subject})
	if userErr != nil {
		return nil, nil, userErr
	}
	if accessError != nil {
		return nil, accessError, nil
	}
	if user == nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "authorization code user no longer exists"}, nil
	}
	if _, ok := IsScopeValidAndExpand(token.Scope, application); !ok {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "authorization code scope is no longer allowed by the application"}, nil
	}
	authenticationContext, contextErr := token.GetAuthenticationContext()
	if contextErr != nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code authentication context is invalid: %s", contextErr.Error()),
		}, nil
	}
	if policyError := validateUserTokenAuthenticationPolicy(user, token.Scope, authenticationContext); policyError != nil {
		return nil, policyError, nil
	}

	var replacement *authorizationCodeTokenReplacement
	if dpopJkt != "" {
		if userErr = ExtendUserWithRolesAndPermissions(user); userErr != nil {
			return nil, nil, userErr
		}
		accessToken, refreshToken, _, tokenErr := generateJwtTokenWithAuthenticationContextAndDPoP(
			application,
			user,
			authenticationContext,
			dpopJkt,
			token.Nonce,
			token.Scope,
			token.Resource,
			host,
			token.Name,
		)
		if tokenErr != nil {
			return nil, nil, tokenErr
		}
		replacement = &authorizationCodeTokenReplacement{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}
	}

	consumed, err := consumeAuthorizationCode(token, dpopJkt, replacement)
	if err != nil {
		return nil, nil, err
	}
	if !consumed {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("authorization code has been used for token: [%s]", token.GetId()),
		}, nil
	}
	token.CodeIsUsed = true
	if dpopJkt != "" {
		token.TokenType = "DPoP"
		token.DPoPJkt = dpopJkt
		token.AccessToken = replacement.AccessToken
		token.RefreshToken = replacement.RefreshToken
		token.AccessTokenHash = getTokenHash(replacement.AccessToken)
		token.RefreshTokenHash = getTokenHash(replacement.RefreshToken)
	}

	return token, nil, nil
}

// GetPasswordToken handles the Resource Owner Password Credentials Grant flow.
func GetPasswordToken(application *Application, username string, password string, scope string, host string) (*Token, *TokenError, error) {
	if application == nil || !IsGrantTypeValid("password", application.GrantTypes) {
		return nil, &TokenError{Error: UnsupportedGrantType, ErrorDescription: "password is not enabled for this application"}, nil
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

	if user.Ldap != "" {
		err = CheckLdapUserPassword(user, password, "en")
	} else {
		// For OAuth users who don't have a password set, they cannot use password grant type
		if user.Password == "" {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "OAuth users cannot use password grant type, please use authorization code flow",
			}, nil
		}
		err = CheckPassword(user, password, "en")
	}
	if err != nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("invalid username or password: %s", err.Error()),
		}, nil
	}

	user, tokenError, err := revalidateUserTokenAccess(application, user)
	if err != nil || tokenError != nil {
		return nil, tokenError, err
	}

	authenticationMethods, err := GetVerifiedPasswordAuthenticationMethods(user, password)
	if err != nil {
		return nil, nil, err
	}
	authenticationContext, err := PreserveAuthenticationContext(AuthenticationContext{
		Subject:  user.GetId(),
		AuthTime: time.Now().Unix(),
		Amr:      authenticationMethods,
	})
	if err != nil {
		return nil, nil, err
	}
	if tokenError = validateUserTokenAuthenticationPolicy(user, scope, authenticationContext); tokenError != nil {
		return nil, tokenError, nil
	}
	if err = ExtendUserWithRolesAndPermissions(user); err != nil {
		return nil, nil, err
	}

	accessToken, refreshToken, tokenName, err := generateJwtTokenWithAuthenticationContext(application, user, authenticationContext, "", scope, "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}
	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Subject:      user.Id,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		GrantType:    "password",
		CodeIsUsed:   true,
	}
	if err = token.SetAuthenticationContext(authenticationContext); err != nil {
		return nil, nil, err
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}

	return token, nil, nil
}

// GetClientCredentialsToken handles the Client Credentials Grant flow.
func GetClientCredentialsToken(application *Application, clientSecret string, scope string, host string) (*Token, *TokenError, error) {
	if application == nil || !IsGrantTypeValid("client_credentials", application.GrantTypes) {
		return nil, &TokenError{Error: UnsupportedGrantType, ErrorDescription: "client_credentials is not enabled for this application"}, nil
	}
	if application.IsPublicClient() || subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_secret is invalid",
		}, nil
	}
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return nil, &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "the requested scope is invalid or not defined in the application",
		}, nil
	}
	scope = expandedScope
	nullUser := &User{
		Owner: application.Owner,
		Id:    application.GetId(),
		Name:  application.Name,
		Type:  "application",
	}

	accessToken, _, tokenName, err := generateJwtToken(application, nullUser, "", "", "", scope, "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}
	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: application.Organization,
		User:         nullUser.Name,
		Subject:      nullUser.Id,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		GrantType:    "client_credentials",
		CodeIsUsed:   true,
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}

	return token, nil, nil
}

// GetImplicitToken handles the Implicit Grant flow (requires password verification).
func GetImplicitToken(application *Application, username string, password string, scope string, nonce string, host string) (*Token, *TokenError, error) {
	return getImplicitTokenForGrant(application, username, password, "token", scope, nonce, host)
}

func getImplicitTokenForGrant(application *Application, username string, password string, requiredGrant string, scope string, nonce string, host string) (*Token, *TokenError, error) {
	if application == nil || !IsGrantTypeValid(requiredGrant, application.GrantTypes) {
		return nil, &TokenError{Error: UnsupportedGrantType, ErrorDescription: fmt.Sprintf("%s is not enabled for this application", requiredGrant)}, nil
	}
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

	if user.Ldap != "" {
		err = CheckLdapUserPassword(user, password, "en")
	} else {
		if user.Password == "" {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "OAuth users cannot use implicit grant type, please use authorization code flow",
			}, nil
		}
		err = CheckPassword(user, password, "en")
	}
	if err != nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("invalid username or password: %s", err.Error()),
		}, nil
	}

	authenticationMethods, err := GetVerifiedPasswordAuthenticationMethods(user, password)
	if err != nil {
		return nil, nil, err
	}
	authenticationContext, err := PreserveAuthenticationContext(AuthenticationContext{
		Subject:  user.GetId(),
		AuthTime: time.Now().Unix(),
		Amr:      authenticationMethods,
	})
	if err != nil {
		return nil, nil, err
	}
	return mintImplicitTokenWithAuthenticationContext(application, username, requiredGrant, scope, nonce, host, &authenticationContext)
}

// GetJwtBearerToken handles the JWT Bearer Grant flow (RFC 7523).
func GetJwtBearerToken(application *Application, assertion string, scope string, nonce string, host string) (*Token, *TokenError, error) {
	const grantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	if application == nil || !IsGrantTypeValid(grantType, application.GrantTypes) {
		return nil, &TokenError{Error: UnsupportedGrantType, ErrorDescription: "JWT bearer is not enabled for this application"}, nil
	}
	ok, claims, err := ValidateJwtAssertion(assertion, application, host)
	if err != nil || !ok {
		if err != nil {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: err.Error(),
			}, err
		}

		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("assertion (JWT) is invalid for application: [%s]", application.GetId()),
		}, nil
	}

	// JWT assertion has already been validated above. Bind the minted refresh
	// credential to that verified assertion instead of creating a token with no
	// authentication evidence.
	user, err := GetUserByFieldsForSharedApp(application, application.Organization, claims.Subject)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "assertion subject does not identify a user"}, nil
	}
	authenticationContext, err := PreserveAuthenticationContext(AuthenticationContext{
		Subject:  user.GetId(),
		AuthTime: time.Now().Unix(),
		Amr:      []string{"jwt"},
	})
	if err != nil {
		return nil, nil, err
	}
	return mintImplicitTokenWithAuthenticationContext(application, user.Name, grantType, scope, nonce, host, &authenticationContext)
}

// GetTokenByUser mints a token for the given user (Implicit flow helper).
func GetTokenByUser(application *Application, user *User, scope string, nonce string, host string) (*Token, error) {
	return nil, fmt.Errorf("trusted authentication context is required to issue a user token")
}

func GetTokenByUserWithAuthenticationContext(application *Application, user *User, scope string, nonce string, host string, authenticationContext AuthenticationContext) (*Token, error) {
	return nil, fmt.Errorf("explicit OAuth grant type is required to issue a user token")
}

func GetTokenByUserForGrantWithAuthenticationContext(application *Application, user *User, requiredGrant string, scope string, nonce string, host string, authenticationContext AuthenticationContext) (*Token, error) {
	if application == nil || !IsGrantTypeValid(requiredGrant, application.GrantTypes) {
		return nil, fmt.Errorf("OAuth grant type %q is not enabled for this application", requiredGrant)
	}
	return getTokenByUserWithAuthenticationContext(application, user, requiredGrant, scope, nonce, host, &authenticationContext)
}

func getTokenByUserWithAuthenticationContext(application *Application, user *User, requiredGrant string, scope string, nonce string, host string, authenticationContext *AuthenticationContext) (*Token, error) {
	if application == nil || authenticationContext == nil {
		return nil, fmt.Errorf("application and trusted authentication context are required")
	}
	preservedContext, err := PreserveAuthenticationContext(*authenticationContext)
	if err != nil {
		return nil, err
	}
	if user == nil || preservedContext.Subject != user.GetId() {
		return nil, fmt.Errorf("authentication context subject does not match user")
	}
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return nil, fmt.Errorf("requested scope is invalid or not defined in the application")
	}
	user, tokenError, err := revalidateUserTokenAccess(application, user)
	if err != nil {
		return nil, err
	}
	if tokenError != nil {
		return nil, fmt.Errorf("%s: %s", tokenError.Error, tokenError.ErrorDescription)
	}
	if tokenError = validateUserTokenAuthenticationPolicy(user, scope, preservedContext); tokenError != nil {
		return nil, fmt.Errorf("%s: %s", tokenError.Error, tokenError.ErrorDescription)
	}
	scope = expandedScope
	authenticationContext = &preservedContext

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, err
	}

	var accessToken, refreshToken, tokenName string
	if authenticationContext == nil {
		accessToken, refreshToken, tokenName, err = generateJwtToken(application, user, "", "", nonce, scope, "", host)
	} else {
		accessToken, refreshToken, tokenName, err = generateJwtTokenWithAuthenticationContext(application, user, *authenticationContext, nonce, scope, "", host)
	}
	if err != nil {
		return nil, err
	}

	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Subject:      user.Id,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		Nonce:        nonce,
		TokenType:    "Bearer",
		GrantType:    requiredGrant,
		CodeIsUsed:   true,
	}
	if authenticationContext != nil {
		if err = token.SetAuthenticationContext(*authenticationContext); err != nil {
			return nil, err
		}
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// GetWechatMiniProgramToken handles the WeChat Mini Program flow.
func GetWechatMiniProgramToken(application *Application, code string, host string, username string, avatar string, lang string) (*Token, *TokenError, error) {
	if application == nil {
		return nil, &TokenError{Error: InvalidClient, ErrorDescription: "application does not exist"}, nil
	}
	mpProvider := GetWechatMiniProgramProvider(application)
	if mpProvider == nil {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "the application does not support wechat mini program",
		}, nil
	}
	provider, err := GetProvider(util.GetId("admin", mpProvider.Name))
	if err != nil {
		return nil, nil, err
	}

	mpIdp := idp.NewWeChatMiniProgramIdProvider(provider.ClientId, provider.ClientSecret)
	session, err := mpIdp.GetSessionByCode(code)
	if err != nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("get wechat mini program session error: %s", err.Error()),
		}, nil
	}

	openId, unionId := session.Openid, session.Unionid
	if openId == "" && unionId == "" {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "the wechat mini program session is invalid",
		}, nil
	}
	user, err := getUserByWechatId(application.Organization, openId, unionId)
	if err != nil {
		return nil, nil, err
	}

	if user == nil {
		if !application.EnableSignUp {
			return nil, &TokenError{
				Error:            InvalidGrant,
				ErrorDescription: "the application does not allow to sign up new account",
			}, nil
		}
		// Add new user
		var name string
		if CheckUsername(username, lang) == "" {
			name = username
		} else {
			name = fmt.Sprintf("wechat-%s", openId)
		}

		// Generate a unique user ID within the confines of the application
		newUserId, idErr := GenerateIdForNewUser(application)
		if idErr != nil {
			// If we fail to generate a unique user ID, we can fallback to a random ID
			newUserId = util.GenerateId()
		}

		user = &User{
			Owner:             application.Organization,
			Id:                newUserId,
			Name:              name,
			Avatar:            avatar,
			SignupApplication: application.Name,
			WeChat:            openId,
			Type:              "normal-user",
			CreatedTime:       util.GetCurrentTime(),
			IsAdmin:           false,
			IsForbidden:       false,
			IsDeleted:         false,
			Properties: map[string]string{
				UserPropertiesWechatOpenId:  openId,
				UserPropertiesWechatUnionId: unionId,
			},
		}
		_, err = AddUser(user, "en")
		if err != nil {
			return nil, nil, err
		}
	}
	user, tokenError, err := revalidateUserTokenAccess(application, user)
	if err != nil || tokenError != nil {
		return nil, tokenError, err
	}

	authenticationContext, err := PreserveAuthenticationContext(AuthenticationContext{
		Subject:  user.GetId(),
		AuthTime: time.Now().Unix(),
		Amr:      []string{"federated"},
		Provider: provider.Name,
	})
	if err != nil {
		return nil, nil, err
	}
	if tokenError = validateUserTokenAuthenticationPolicy(user, "", authenticationContext); tokenError != nil {
		return nil, tokenError, nil
	}
	if err = ExtendUserWithRolesAndPermissions(user); err != nil {
		return nil, nil, err
	}
	accessToken, refreshToken, tokenName, err := generateJwtTokenWithAuthenticationContext(application, user, authenticationContext, "", "", "", host)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}

	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Subject:      user.Id,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        "",
		TokenType:    "Bearer",
		GrantType:    "wechat_miniprogram",
		CodeIsUsed:   true,
	}
	if err = token.SetAuthenticationContext(authenticationContext); err != nil {
		return nil, nil, err
	}
	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}
	return token, nil, nil
}

// GetTokenExchangeToken handles the Token Exchange Grant flow (RFC 8693).
// Exchanges a subject token for a new token with different audience or scope.
func GetTokenExchangeToken(application *Application, clientSecret string, subjectToken string, subjectTokenType string, audience string, scope string, host string, dpopJkts ...string) (*Token, *TokenError, error) {
	const grantType = "urn:ietf:params:oauth:grant-type:token-exchange"
	if application == nil || !IsGrantTypeValid(grantType, application.GrantTypes) {
		return nil, &TokenError{Error: UnsupportedGrantType, ErrorDescription: "token exchange is not enabled for this application"}, nil
	}
	if application.IsPublicClient() || subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, &TokenError{
			Error:            InvalidClient,
			ErrorDescription: "client_secret is invalid",
		}, nil
	}

	if subjectToken == "" {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "subject_token is required",
		}, nil
	}

	// This endpoint exchanges active Casdoor access tokens only. Refresh tokens
	// and ambiguous generic JWTs must use their dedicated flows.
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: fmt.Sprintf("unsupported subject_token_type: %s", subjectTokenType),
		}, nil
	}
	if audience != "" && audience != application.ClientId {
		return nil, &TokenError{
			Error:            InvalidRequest,
			ErrorDescription: "audience must identify the requesting application",
		}, nil
	}

	dpopJkt := ""
	if len(dpopJkts) > 0 {
		dpopJkt = dpopJkts[0]
	}
	validatedSubject, tokenError, err := parseAndValidateSubjectToken(subjectToken, application.ClientId, dpopJkt)
	if err != nil {
		return nil, nil, err
	}
	if tokenError != nil {
		return nil, tokenError, nil
	}

	user, err := getUser(validatedSubject.Owner, validatedSubject.Name)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("user from subject_token does not exist: %s", util.GetId(validatedSubject.Owner, validatedSubject.Name)),
		}, nil
	}
	if user.Id != validatedSubject.Subject {
		return nil, &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: "subject_token subject does not match the persisted user",
		}, nil
	}

	user, tokenError, err = revalidateUserTokenAccess(application, user)
	if err != nil || tokenError != nil {
		return nil, tokenError, err
	}

	// If scope is not provided, use the scope from the subject token.
	// If scope is provided, it should be a subset of the subject token's scope (downscoping).
	if scope == "" {
		scope = validatedSubject.Scope
	}
	expandedScope, ok := IsScopeValidAndExpand(scope, application)
	if !ok {
		return nil, &TokenError{
			Error:            InvalidScope,
			ErrorDescription: "requested scope is invalid or not defined in the requesting application",
		}, nil
	}
	subjectScopes := make(map[string]struct{})
	for _, subjectScope := range strings.Fields(validatedSubject.Scope) {
		subjectScopes[subjectScope] = struct{}{}
	}
	for _, requestedScope := range strings.Fields(expandedScope) {
		if _, found := subjectScopes[requestedScope]; !found {
			return nil, &TokenError{
				Error:            InvalidScope,
				ErrorDescription: fmt.Sprintf("requested scope %q is not in the subject token grant", requestedScope),
			}, nil
		}
	}
	scope = expandedScope
	if tokenError = validateUserTokenAuthenticationPolicy(user, scope, validatedSubject.AuthenticationContext); tokenError != nil {
		return nil, tokenError, nil
	}

	err = ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		return nil, nil, err
	}

	accessToken, refreshToken, tokenName, err := generateJwtTokenWithAuthenticationContextAndDPoP(
		application,
		user,
		validatedSubject.AuthenticationContext,
		dpopJkt,
		"",
		scope,
		audience,
		host,
	)
	if err != nil {
		return nil, &TokenError{
			Error:            EndpointError,
			ErrorDescription: fmt.Sprintf("generate jwt token error: %s", err.Error()),
		}, nil
	}

	token := &Token{
		Owner:        application.Owner,
		Name:         tokenName,
		CreatedTime:  util.GetCurrentTime(),
		Application:  application.Name,
		Organization: user.Owner,
		User:         user.Name,
		Subject:      user.Id,
		Code:         util.GenerateClientId(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(application.ExpireInHours * float64(hourSeconds)),
		Scope:        scope,
		TokenType:    "Bearer",
		GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
		CodeIsUsed:   true,
		Resource:     audience,
		DPoPJkt:      dpopJkt,
	}
	if dpopJkt != "" {
		token.TokenType = "DPoP"
	}
	if err = token.SetAuthenticationContext(validatedSubject.AuthenticationContext); err != nil {
		return nil, nil, err
	}

	_, err = AddToken(token)
	if err != nil {
		return nil, nil, err
	}

	return token, nil, nil
}

func GetAccessTokenByUser(user *User, host string, authenticationContexts ...AuthenticationContext) (string, error) {
	if len(authenticationContexts) == 0 {
		return "", fmt.Errorf("trusted authentication context is required to issue a user access token")
	}
	authenticationContext, err := PreserveAuthenticationContext(authenticationContexts[0])
	if err != nil {
		return "", err
	}
	if authenticationContext.Subject != user.GetId() {
		return "", fmt.Errorf("authentication context subject does not match user")
	}
	application, err := GetApplicationByUser(user)
	if err != nil {
		return "", err
	}
	if application == nil {
		return "", fmt.Errorf("the application for user %s is not found", user.Id)
	}

	token, err := GetTokenByUserForGrantWithAuthenticationContext(application, user, "authorization_code", "profile", "", host, authenticationContext)
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}
