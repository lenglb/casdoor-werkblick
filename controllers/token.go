// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"encoding/json"
	"fmt"

	"github.com/beego/beego/v2/core/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetTokens
// @Title GetTokens
// @Tag Token API
// @Description get tokens
// @Param   owner     query    string  true        "The organization name (e.g., built-in)"
// @Param   pageSize     query    string  true        "The size of each page"
// @Param   p     query    string  true        "The number of the page"
// @Success 200 {array} object.Token The Response object
// @router /get-tokens [get]
func (c *ApiController) GetTokens() {
	owner := c.Ctx.Input.Query("owner")
	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")
	organization := c.Ctx.Input.Query("organization")
	if limit == "" || page == "" {
		token, err := object.GetTokens(owner, organization)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(object.MaskTokensForResponse(token))
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetTokenCount(owner, organization, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.NewPaginator(c.Ctx.Request, limit, count)
		tokens, err := object.GetPaginationTokens(owner, organization, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(object.MaskTokensForResponse(tokens), paginator.Nums())
	}
}

// GetToken
// @Title GetToken
// @Tag Token API
// @Description get token
// @Param   id     query    string  true        "The token ID in format: organization/token-name (e.g., built-in/token-123456)"
// @Success 200 {object} object.Token The Response object
// @router /get-token [get]
func (c *ApiController) GetToken() {
	id := c.Ctx.Input.Query("id")
	organization := c.Ctx.Input.Query("organization")
	token, err := object.GetToken(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if token == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The token: %s does not exist"), id))
		return
	}

	isGlobalAdmin, _ := c.isGlobalAdmin()
	if token.Organization != organization && !isGlobalAdmin {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	c.ResponseOk(object.MaskTokenForResponse(token))
}

// UpdateToken
// @Title UpdateToken
// @Tag Token API
// @Description update token
// @Param   id     query    string  true        "The token ID in format: organization/token-name (e.g., built-in/token-123456)"
// @Param   body    body   object.Token  true        "Details of the token"
// @Success 200 {object} controllers.Response The Response object
// @router /update-token [post]
func (c *ApiController) UpdateToken() {
	id := c.Ctx.Input.Query("id")

	var token object.Token
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &token)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateToken(id, &token, c.IsGlobalAdmin()))
	c.ServeJSON()
}

// AddToken
// @Title AddToken
// @Tag Token API
// @Description add token
// @Param   body    body   object.Token  true        "Details of the token"
// @Success 200 {object} controllers.Response The Response object
// @router /add-token [post]
func (c *ApiController) AddToken() {
	c.ResponseError("manual token creation is disabled; use an OAuth grant")
}

// DeleteToken
// @Tag Token API
// @Title DeleteToken
// @Description delete token
// @Param   body    body   object.Token  true        "Details of the token"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-token [post]
func (c *ApiController) DeleteToken() {
	var token object.Token
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &token)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteToken(&token))
	c.ServeJSON()
}

// GetOAuthToken
// @Title GetOAuthToken
// @Tag Token API
// @Description get OAuth access token
// @Param   grant_type     query    string  true        "OAuth grant type"
// @Param   client_id     query    string  true        "OAuth client id"
// @Param   client_secret     query    string  true        "OAuth client secret"
// @Param   code     query    string  true        "OAuth code"
// @Param   redirect_uri     query    string  true        "Exact redirect URI from the authorization request"
// @Success 200 {object} object.TokenWrapper The Response object
// @Success 400 {object} object.TokenError The Response object
// @Success 401 {object} object.TokenError The Response object
// @router /login/oauth/access_token [post]
func (c *ApiController) GetOAuthToken() {
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Ctx.Output.Header("Pragma", "no-cache")
	clientId := c.Ctx.Input.Query("client_id")
	clientSecret := c.Ctx.Input.Query("client_secret")
	assertion := c.Ctx.Input.Query("assertion")
	clientAssertion := c.Ctx.Input.Query("client_assertion")
	clientAssertionType := c.Ctx.Input.Query("client_assertion_type")
	grantType := c.Ctx.Input.Query("grant_type")
	code := c.Ctx.Input.Query("code")
	verifier := c.Ctx.Input.Query("code_verifier")
	redirectUri := c.Ctx.Input.Query("redirect_uri")
	scope := c.Ctx.Input.Query("scope")
	nonce := c.Ctx.Input.Query("nonce")
	username := c.Ctx.Input.Query("username")
	password := c.Ctx.Input.Query("password")
	tag := c.Ctx.Input.Query("tag")
	avatar := c.Ctx.Input.Query("avatar")
	refreshToken := c.Ctx.Input.Query("refresh_token")
	deviceCode := c.Ctx.Input.Query("device_code")
	subjectToken := c.Ctx.Input.Query("subject_token")
	subjectTokenType := c.Ctx.Input.Query("subject_token_type")
	audience := c.Ctx.Input.Query("audience")
	resource := c.Ctx.Input.Query("resource")

	if clientId == "" && clientSecret == "" {
		clientId, clientSecret, _ = c.Ctx.Request.BasicAuth()
	}

	if len(c.Ctx.Input.RequestBody) != 0 && grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		// If clientId is empty, try to read data from RequestBody
		var tokenRequest TokenRequest
		err := json.Unmarshal(c.Ctx.Input.RequestBody, &tokenRequest)
		if err == nil {
			if clientId == "" {
				clientId = tokenRequest.ClientId
			}
			if clientSecret == "" {
				clientSecret = tokenRequest.ClientSecret
			}
			if clientAssertion == "" {
				clientAssertion = tokenRequest.ClientAssertion
			}
			if clientAssertionType == "" {
				clientAssertionType = tokenRequest.ClientAssertionType
			}
			if grantType == "" {
				grantType = tokenRequest.GrantType
			}
			if code == "" {
				code = tokenRequest.Code
			}
			if verifier == "" {
				verifier = tokenRequest.Verifier
			}
			if redirectUri == "" {
				redirectUri = tokenRequest.RedirectUri
			}
			if scope == "" {
				scope = tokenRequest.Scope
			}
			if nonce == "" {
				nonce = tokenRequest.Nonce
			}
			if username == "" {
				username = tokenRequest.Username
			}
			if password == "" {
				password = tokenRequest.Password
			}
			if tag == "" {
				tag = tokenRequest.Tag
			}
			if avatar == "" {
				avatar = tokenRequest.Avatar
			}
			if refreshToken == "" {
				refreshToken = tokenRequest.RefreshToken
			}
			if subjectToken == "" {
				subjectToken = tokenRequest.SubjectToken
			}
			if subjectTokenType == "" {
				subjectTokenType = tokenRequest.SubjectTokenType
			}
			if audience == "" {
				audience = tokenRequest.Audience
			}
			if resource == "" {
				resource = tokenRequest.Resource
			}
			if assertion == "" {
				assertion = tokenRequest.Assertion
			}
		}
	}

	// Extract DPoP proof header (RFC 9449). Empty string when DPoP is not used.
	dpopProof := c.Ctx.Request.Header.Get("DPoP")

	host := c.Ctx.Request.Host
	if grantType == "urn:ietf:params:oauth:grant-type:device_code" && deviceCode == "" {
		c.Data["json"] = &object.TokenError{
			Error:            "invalid_request",
			ErrorDescription: "device_code parameter is required for this grant type",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}
	if deviceCode != "" && grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		c.Data["json"] = &object.TokenError{
			Error:            object.InvalidRequest,
			ErrorDescription: "device_code is only valid with the device_code grant type",
		}
		c.SetTokenErrorHttpStatus()
		c.ServeJSON()
		return
	}

	clientAuthentication, tokenError := c.getOAuthClientAuthentication()
	if tokenError != nil {
		c.ResponseTokenError(tokenError.Error, tokenError.ErrorDescription)
		return
	}
	clientId = clientAuthentication.ClientId
	clientSecret = clientAuthentication.ClientSecret
	token, err := object.GetOAuthTokenWithRedirectUri(grantType, clientId, clientSecret, code, verifier, redirectUri, scope, nonce, username, password, host, refreshToken, tag, avatar, c.GetAcceptLanguage(), subjectToken, subjectTokenType, assertion, clientAssertion, clientAssertionType, audience, resource, deviceCode, dpopProof, clientAuthentication)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = token
	c.SetTokenErrorHttpStatus()
	c.ServeJSON()
}

// RefreshToken
// @Title RefreshToken
// @Tag Token API
// @Description refresh OAuth access token
// @Param   grant_type     query    string  true        "OAuth grant type"
// @Param	refresh_token	query	string	true		"OAuth refresh token"
// @Param   scope     query    string  true        "OAuth scope"
// @Param   client_id     query    string  true        "OAuth client id"
// @Param   client_secret     query    string  false        "OAuth client secret"
// @Success 200 {object} object.TokenWrapper The Response object
// @Success 400 {object} object.TokenError The Response object
// @Success 401 {object} object.TokenError The Response object
// @router /login/oauth/refresh_token [post]
func (c *ApiController) RefreshToken() {
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Ctx.Output.Header("Pragma", "no-cache")
	grantType := c.Ctx.Input.Query("grant_type")
	refreshToken := c.Ctx.Input.Query("refresh_token")
	scope := c.Ctx.Input.Query("scope")
	clientId := c.Ctx.Input.Query("client_id")
	clientSecret := c.Ctx.Input.Query("client_secret")
	host := c.Ctx.Request.Host

	if clientId == "" {
		// If clientID is empty, try to read data from RequestBody
		var tokenRequest TokenRequest
		if err := json.Unmarshal(c.Ctx.Input.RequestBody, &tokenRequest); err == nil {
			clientId = tokenRequest.ClientId
			clientSecret = tokenRequest.ClientSecret
			grantType = tokenRequest.GrantType
			scope = tokenRequest.Scope
			refreshToken = tokenRequest.RefreshToken
		}
	}

	ok, application, clientId, authenticatedClientSecret, err := c.ValidateOAuth(true)
	if err != nil || !ok {
		return
	}
	clientSecret = authenticatedClientSecret

	dpopProof := c.Ctx.Request.Header.Get("DPoP")
	dpopHtu := object.GetDPoPHtu(host, c.Ctx.Request.URL.EscapedPath())
	refreshToken2, err := object.RefreshToken(application, grantType, refreshToken, scope, clientId, clientSecret, host, dpopProof, dpopHtu)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = refreshToken2
	c.SetTokenErrorHttpStatus()
	c.ServeJSON()
}

func (c *ApiController) ResponseTokenError(errorMsg string, errorDescription string) {
	c.Data["json"] = &object.TokenError{
		Error:            errorMsg,
		ErrorDescription: errorDescription,
	}
	c.SetTokenErrorHttpStatus()
	c.ServeJSON()
}

func (c *ApiController) ValidateOAuth(ignoreValidSecret bool) (ok bool, application *object.Application, clientId, clientSecret string, err error) {
	// The old ignoreValidSecret path let callers postpone authentication to a
	// grant implementation and thereby lose the credential transport. All token
	// endpoints now enforce the registered method before processing credentials.
	_ = ignoreValidSecret
	authentication, tokenError := c.getOAuthClientAuthentication()
	if tokenError != nil {
		c.ResponseTokenError(tokenError.Error, tokenError.ErrorDescription)
		return false, nil, "", "", nil
	}

	application, tokenError, err = object.AuthenticateOAuthClient(authentication, c.Ctx.Request.Host)
	if err != nil {
		c.ResponseTokenError(object.InvalidClient, err.Error())
		return false, nil, "", "", err
	}
	if tokenError != nil {
		c.ResponseTokenError(tokenError.Error, tokenError.ErrorDescription)
		return false, nil, "", "", nil
	}

	return true, application, authentication.ClientId, authentication.EffectiveClientSecret(application), nil
}

// IntrospectToken
// @Title IntrospectToken
// @Tag Login API
// @Description The introspection endpoint is an OAuth 2.0 endpoint that takes a
// parameter representing an OAuth 2.0 token and returns a JSON document
// representing the meta information surrounding the
// token, including whether this token is currently active.
// This endpoint support Basic Authorization and authorization defined in RFC 7523.
//
// @Param token formData string true "access_token's value or refresh_token's value"
// @Param token_type_hint formData string true "the token type access_token or refresh_token"
// @Success 200 {object} object.IntrospectionResponse The Response object
// @Success 400 {object} object.TokenError The Response object
// @Success 401 {object} object.TokenError The Response object
// @router /login/oauth/introspect [post]
func (c *ApiController) IntrospectToken() {
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Ctx.Output.Header("Pragma", "no-cache")
	tokenValue := c.Ctx.Input.Query("token")

	ok, application, _, _, err := c.ValidateOAuth(false)
	if err != nil || !ok {
		return
	}
	if application.IsPublicClient() {
		c.ResponseTokenError(object.InvalidClient, "public clients cannot use token introspection")
		return
	}

	respondWithInactiveToken := func() {
		c.Data["json"] = &object.IntrospectionResponse{Active: false}
		c.ServeJSON()
	}

	tokenTypeHint := c.Ctx.Input.Query("token_type_hint")
	var token *object.Token
	credentialType := ""
	switch tokenTypeHint {
	case "", "access_token", "access-token", "refresh_token", "refresh-token":
	default:
		c.ResponseTokenError(object.InvalidRequest, "unsupported token_type_hint")
		return
	}
	if tokenTypeHint == "access_token" || tokenTypeHint == "access-token" {
		credentialType = "access-token"
		token, err = object.GetTokenByAccessToken(tokenValue)
	} else if tokenTypeHint == "refresh_token" || tokenTypeHint == "refresh-token" {
		credentialType = "refresh-token"
		token, err = object.GetTokenByRefreshToken(tokenValue)
	} else {
		token, err = object.GetTokenByAccessToken(tokenValue)
		credentialType = "access-token"
		if err == nil && token == nil {
			token, err = object.GetTokenByRefreshToken(tokenValue)
			credentialType = "refresh-token"
		}
	}
	if err != nil {
		c.ResponseTokenError(object.InvalidRequest, err.Error())
		return
	}
	if token == nil || token.ExpiresIn <= 0 {
		respondWithInactiveToken()
		return
	}
	// An authenticated client must not be able to inspect credentials issued
	// to another application, even when it knows the opaque/JWT value.
	if token.Owner != application.Owner || token.Application != application.Name {
		respondWithInactiveToken()
		return
	}

	introspectionResponse := object.IntrospectionResponse{
		Active:    true,
		Scope:     token.Scope,
		ClientId:  application.ClientId,
		Username:  token.User,
		TokenType: token.TokenType,
	}
	if token.DPoPJkt != "" {
		introspectionResponse.Cnf = &object.DPoPConfirmation{JKT: token.DPoPJkt}
	}

	if credentialType == "refresh-token" {
		claims, parseErr := object.ParseRefreshJwtTokenByApplication(tokenValue, application)
		if parseErr != nil || claims.Azp != application.ClientId || claims.Scope != token.Scope || !object.DPoPConfirmationMatches(claims.Cnf, token.DPoPJkt) {
			respondWithInactiveToken()
			return
		}
		introspectionResponse.Exp = object.NumericDateUnix(claims.ExpiresAt)
		introspectionResponse.Iat = object.NumericDateUnix(claims.IssuedAt)
		introspectionResponse.Nbf = object.NumericDateUnix(claims.NotBefore)
		introspectionResponse.Sub = claims.Subject
		introspectionResponse.Aud = claims.Audience
		introspectionResponse.Iss = claims.Issuer
		introspectionResponse.Jti = claims.ID
	} else if application.TokenFormat == "JWT-Standard" {
		claims, parseErr := object.ParseStandardJwtTokenByApplication(tokenValue, application)
		if parseErr != nil || claims.TokenType != "access-token" || claims.Azp != application.ClientId || !object.DPoPConfirmationMatches(claims.Cnf, token.DPoPJkt) {
			respondWithInactiveToken()
			return
		}
		introspectionResponse.Exp = object.NumericDateUnix(claims.ExpiresAt)
		introspectionResponse.Iat = object.NumericDateUnix(claims.IssuedAt)
		introspectionResponse.Nbf = object.NumericDateUnix(claims.NotBefore)
		introspectionResponse.Sub = claims.Subject
		introspectionResponse.Aud = claims.Audience
		introspectionResponse.Iss = claims.Issuer
		introspectionResponse.Jti = claims.ID
	} else {
		claims, parseErr := object.ParseJwtTokenByApplication(tokenValue, application)
		if parseErr != nil || claims.TokenType != "access-token" || claims.Azp != application.ClientId || !object.DPoPConfirmationMatches(claims.Cnf, token.DPoPJkt) {
			respondWithInactiveToken()
			return
		}
		introspectionResponse.Exp = object.NumericDateUnix(claims.ExpiresAt)
		introspectionResponse.Iat = object.NumericDateUnix(claims.IssuedAt)
		introspectionResponse.Nbf = object.NumericDateUnix(claims.NotBefore)
		introspectionResponse.Sub = claims.Subject
		introspectionResponse.Aud = claims.Audience
		introspectionResponse.Iss = claims.Issuer
		introspectionResponse.Jti = claims.ID
	}

	c.Data["json"] = introspectionResponse
	c.ServeJSON()
}
