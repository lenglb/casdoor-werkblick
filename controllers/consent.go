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
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
)

type consentOAuthRequest struct {
	Application  string   `json:"application"`
	Scopes       []string `json:"grantedScopes"`
	ClientId     string   `json:"clientId"`
	ResponseType string   `json:"responseType"`
	ResponseMode string   `json:"responseMode"`
	RedirectUri  string   `json:"redirectUri"`
	Scope        string   `json:"scope"`
	State        string   `json:"state"`
	Nonce        string   `json:"nonce"`
	Challenge    string   `json:"challenge"`
	Resource     string   `json:"resource"`
}

func (request consentOAuthRequest) matchesAuthorizationRequest(expected object.AuthorizationRequest) bool {
	return request.ClientId == expected.ClientId &&
		request.ResponseType == expected.ResponseType &&
		request.ResponseMode == expected.ResponseMode &&
		request.RedirectUri == expected.RedirectUri &&
		request.Scope == expected.Scope &&
		request.State == expected.State &&
		request.Nonce == expected.Nonce &&
		request.Challenge == expected.CodeChallenge &&
		request.Resource == expected.Resource
}

func (c *ApiController) validateConsentOAuthRequest(userId string, request consentOAuthRequest) (object.PendingAuthentication, object.AuthorizationRequest, *object.Application, error) {
	pendingAuthentication, err := c.getPendingAuthentication()
	if err != nil {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, err
	}
	if pendingAuthentication.Context.Subject != userId {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("invalid user")
	}
	if pendingAuthentication.Request == nil {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("invalid OAuth request")
	}
	authorizationRequest := pendingAuthentication.Request.Clone()
	if !request.matchesAuthorizationRequest(authorizationRequest) {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("OAuth request does not match pending authentication")
	}

	application, err := object.GetApplicationByClientId(authorizationRequest.ClientId)
	if err != nil {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, err
	}
	if application == nil {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("invalid client_id")
	}
	if pendingAuthentication.FlowType != ResponseTypeCode || pendingAuthentication.ApplicationId != application.GetId() {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("invalid OAuth request")
	}
	if request.Application != application.GetId() {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("invalid application")
	}
	if !application.IsRedirectUriValid(authorizationRequest.RedirectUri) {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("invalid redirect_uri")
	}

	currentAuthenticationContext, err := c.getCurrentAuthenticationContext()
	if err != nil || !pendingAuthentication.Context.Equal(currentAuthenticationContext) {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("fresh authentication is required")
	}
	if authorizationRequest.ExceedsMaxAge(currentAuthenticationContext, time.Now().Unix()) {
		return object.PendingAuthentication{}, object.AuthorizationRequest{}, nil, fmt.Errorf("fresh authentication is required")
	}

	return pendingAuthentication, authorizationRequest, application, nil
}

// RevokeConsent revokes a consent record
// @Title RevokeConsent
// @Tag Consent API
// @Description revoke a consent record
// @Param body body object.ConsentRecord true "The consent object"
// @Success 200 {object} controllers.Response The Response object
// @router /revoke-consent [post]
func (c *ApiController) RevokeConsent() {
	userId := c.GetSessionUsername()
	if userId == "" {
		c.ResponseError(c.T("general:Please login first"))
		return
	}

	var consent object.ConsentRecord
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &consent)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Validate that consent.Application is not empty
	if consent.Application == "" {
		c.ResponseError(c.T("general:Application cannot be empty"))
		return
	}

	// Validate that GrantedScopes is not empty when scope-specific revoke is requested
	if len(consent.GrantedScopes) == 0 {
		c.ResponseError(c.T("general:Granted scopes cannot be empty"))
		return
	}

	userObj, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if userObj == nil {
		c.ResponseError(c.T("general:The user doesn't exist"))
		return
	}

	newScopes := []object.ConsentRecord{}
	for _, record := range userObj.ApplicationScopes {
		if record.Application != consent.Application {
			// skip other applications
			newScopes = append(newScopes, record)
			continue
		}
		// revoke specified scopes
		revokeSet := make(map[string]bool)
		for _, s := range consent.GrantedScopes {
			revokeSet[s] = true
		}
		remaining := []string{}
		for _, s := range record.GrantedScopes {
			if !revokeSet[s] {
				remaining = append(remaining, s)
			}
		}
		if len(remaining) > 0 {
			// still have remaining scopes, keep the record and update
			record.GrantedScopes = remaining
			newScopes = append(newScopes, record)
		}
		// otherwise the application authorization is revoked, delete the whole record
	}
	userObj.ApplicationScopes = newScopes
	success, err := object.UpdateUser(userObj.GetId(), userObj, nil, false)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(success)
}

// GrantConsent grants consent for an OAuth application and returns authorization code
// @Title GrantConsent
// @Tag Consent API
// @Description grant consent for an OAuth application and get authorization code
// @Param body body object.ConsentRecord true "The consent object with OAuth parameters"
// @Success 200 {object} controllers.Response The Response object
// @router /grant-consent [post]
func (c *ApiController) GrantConsent() {
	userId := c.GetSessionUsername()
	if userId == "" {
		c.ResponseError(c.T("general:Please login first"))
		return
	}

	var request consentOAuthRequest

	err := json.Unmarshal(c.Ctx.Input.RequestBody, &request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	pendingAuthentication, authorizationRequest, application, err := c.validateConsentOAuthRequest(userId, request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	requestedScopes := map[string]struct{}{}
	for _, scope := range strings.Fields(authorizationRequest.Scope) {
		requestedScopes[scope] = struct{}{}
	}
	for _, scope := range request.Scopes {
		if _, ok := requestedScopes[scope]; !ok {
			c.ResponseError(c.T("general:Invalid scope"))
			return
		}
	}
	if err = c.consumePendingAuthentication(pendingAuthentication.TransactionId, pendingAuthentication.ExpiresAt); err != nil {
		c.ResponseError(err.Error())
		return
	}

	// Update user's ApplicationScopes
	userObj, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if userObj == nil {
		c.ResponseError(c.T("general:User not found"))
		return
	}

	appId := application.GetId()
	found := false
	// Insert new scope into existing applicationScopes
	for i, record := range userObj.ApplicationScopes {
		if record.Application == appId {
			existing := make(map[string]bool)
			for _, s := range userObj.ApplicationScopes[i].GrantedScopes {
				existing[s] = true
			}
			for _, s := range request.Scopes {
				if !existing[s] {
					userObj.ApplicationScopes[i].GrantedScopes = append(userObj.ApplicationScopes[i].GrantedScopes, s)
					existing[s] = true
				}
			}
			found = true
			break
		}
	}
	// create a new applicationScopes if not found
	if !found {
		uniqueScopes := []string{}
		existing := make(map[string]bool)
		for _, s := range request.Scopes {
			if !existing[s] {
				uniqueScopes = append(uniqueScopes, s)
				existing[s] = true
			}
		}
		userObj.ApplicationScopes = append(userObj.ApplicationScopes, object.ConsentRecord{
			Application:   appId,
			GrantedScopes: uniqueScopes,
		})
	}

	_, err = object.UpdateUser(userObj.GetId(), userObj, []string{"application_scopes"}, false)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	// The issued code must carry only the scopes the user actually granted.
	// Keeping the original requested scope here would turn a partial or empty
	// consent selection into full authorization.
	authorizationRequest.Scope = strings.Join(request.Scopes, " ")

	// Now get the OAuth code
	code, err := object.GetOAuthCodeWithAuthenticationContext(
		userId,
		authorizationRequest.ClientId,
		pendingAuthentication.Context,
		authorizationRequest.ResponseType,
		authorizationRequest.RedirectUri,
		authorizationRequest.Scope,
		authorizationRequest.State,
		authorizationRequest.Nonce,
		authorizationRequest.CodeChallenge,
		authorizationRequest.Resource,
		c.Ctx.Request.Host,
		c.GetAcceptLanguage(),
	)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if code == nil {
		c.ResponseError("failed to create OAuth authorization code")
		return
	}
	if code.Message != "" {
		c.ResponseError(code.Message)
		return
	}
	if code.Code == "" {
		c.ResponseError("failed to create OAuth authorization code")
		return
	}

	c.ResponseOk(code.Code)
}

// DenyConsent rejects a server-bound OAuth consent transaction.
// @Title DenyConsent
// @Tag Consent API
// @Description deny consent for an OAuth application
// @Success 200 {object} controllers.Response The Response object
// @router /deny-consent [post]
func (c *ApiController) DenyConsent() {
	userId := c.GetSessionUsername()
	if userId == "" {
		c.ResponseError(c.T("general:Please login first"))
		return
	}

	var request consentOAuthRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &request); err != nil {
		c.ResponseError(err.Error())
		return
	}

	pendingAuthentication, authorizationRequest, _, err := c.validateConsentOAuthRequest(userId, request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if err = c.consumePendingAuthentication(pendingAuthentication.TransactionId, pendingAuthentication.ExpiresAt); err != nil {
		c.ResponseError(err.Error())
		return
	}

	redirectUrl, err := buildOAuthErrorCallbackUrl(
		authorizationRequest.RedirectUri,
		authorizationRequest.State,
		"access_denied",
		"User denied consent",
	)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(redirectUrl)
}

func buildOAuthErrorCallbackUrl(redirectUri string, state string, errorCode string, description string) (string, error) {
	redirectUrl, err := url.Parse(redirectUri)
	if err != nil {
		return "", fmt.Errorf("invalid redirect_uri: %w", err)
	}
	if redirectUrl.Scheme == "" {
		return "", fmt.Errorf("invalid redirect_uri: absolute URI required")
	}
	switch strings.ToLower(redirectUrl.Scheme) {
	case "javascript", "data", "vbscript", "file":
		return "", fmt.Errorf("invalid redirect_uri scheme")
	}

	query := redirectUrl.Query()
	query.Set("error", errorCode)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	redirectUrl.RawQuery = query.Encode()
	return redirectUrl.String(), nil
}
