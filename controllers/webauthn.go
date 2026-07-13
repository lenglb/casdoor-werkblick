// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const webAuthnAuthenticationSessionKey = "authentication"

// webAuthnSigninSession binds a single WebAuthn challenge to the OAuth
// authorization request that caused it. The whole value is serialized under a
// single session key so the ceremony and its authorization context cannot be
// mixed independently by concurrent browser tabs.
type webAuthnSigninSession struct {
	Ceremony      webauthn.SessionData         `json:"ceremony"`
	Request       *object.AuthorizationRequest `json:"request,omitempty"`
	ResponseType  string                       `json:"response_type"`
	TransactionId string                       `json:"transaction_id"`
}

var consumedWebAuthnSigninTransactions sync.Map

func newWebAuthnSigninSession(sessionData webauthn.SessionData, responseType string, request *object.AuthorizationRequest) (webAuthnSigninSession, error) {
	if responseType == "" {
		responseType = ResponseTypeLogin
	}

	var requestCopy *object.AuthorizationRequest
	if request != nil {
		cloned := request.Clone()
		requestCopy = &cloned
	}

	session := webAuthnSigninSession{
		Ceremony:      sessionData,
		Request:       requestCopy,
		ResponseType:  responseType,
		TransactionId: util.GenerateId(),
	}
	if err := session.validate(time.Now()); err != nil {
		return webAuthnSigninSession{}, err
	}
	return session, nil
}

func (session webAuthnSigninSession) validate(now time.Time) error {
	if strings.TrimSpace(session.TransactionId) == "" {
		return fmt.Errorf("WebAuthn authentication transaction id must not be empty")
	}
	if strings.TrimSpace(session.Ceremony.Challenge) == "" {
		return fmt.Errorf("WebAuthn authentication challenge must not be empty")
	}
	if session.Ceremony.Expires.IsZero() || !session.Ceremony.Expires.After(now) {
		return fmt.Errorf("WebAuthn authentication challenge has expired")
	}

	switch session.ResponseType {
	case ResponseTypeLogin, ResponseTypeToken, ResponseTypeIdToken, ResponseTypeSaml, ResponseTypeCas, ResponseTypeDevice:
		if session.Request != nil {
			return fmt.Errorf("non-code WebAuthn authentication must not contain an OAuth authorization request")
		}
	case ResponseTypeCode:
		if session.Request == nil {
			return fmt.Errorf("code WebAuthn authentication requires an OAuth authorization request")
		}
		if err := session.Request.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("WebAuthn authentication response type %q is not supported", session.ResponseType)
	}
	return nil
}

func (session webAuthnSigninSession) matchesContinuation(responseType string, request *object.AuthorizationRequest) error {
	if responseType == "" {
		responseType = ResponseTypeLogin
	}
	if responseType != session.ResponseType {
		return fmt.Errorf("WebAuthn authentication response type does not match the challenge")
	}
	if session.Request == nil || request == nil {
		if session.Request != nil || request != nil {
			return fmt.Errorf("WebAuthn OAuth authorization request does not match the challenge")
		}
		return nil
	}
	if !session.Request.Equal(*request) {
		return fmt.Errorf("WebAuthn OAuth authorization request does not match the challenge")
	}
	return nil
}

func claimWebAuthnSigninTransaction(transactionId string, expiresAt int64, now int64) bool {
	consumedWebAuthnSigninTransactions.Range(func(key, value any) bool {
		if expiry, ok := value.(int64); !ok || expiry < now {
			consumedWebAuthnSigninTransactions.Delete(key)
		}
		return true
	})
	_, loaded := consumedWebAuthnSigninTransactions.LoadOrStore(transactionId, expiresAt)
	return !loaded
}

// consumeWebAuthnSigninSession removes the challenge before any assertion is
// verified. Therefore every finish attempt, successful or not, is terminal.
// The process-local transaction claim closes the concurrent read/delete race;
// clustered deployments still require an atomic shared session backend.
func (c *ApiController) consumeWebAuthnSigninSession() (webAuthnSigninSession, error) {
	value := c.GetSession(webAuthnAuthenticationSessionKey)
	if value == nil {
		return webAuthnSigninSession{}, fmt.Errorf("WebAuthn authentication challenge is missing")
	}
	if err := c.DelSession(webAuthnAuthenticationSessionKey); err != nil {
		return webAuthnSigninSession{}, fmt.Errorf("delete WebAuthn authentication challenge: %w", err)
	}
	// Persist the deletion before parsing or verifying attacker-controlled
	// assertion input. This also makes malformed finish attempts terminal for
	// external session stores rather than waiting for response teardown.
	c.Ctx.Input.CruSession.SessionRelease(context.Background(), c.Ctx.ResponseWriter)

	serialized, ok := value.(string)
	if !ok || strings.TrimSpace(serialized) == "" {
		return webAuthnSigninSession{}, fmt.Errorf("WebAuthn authentication session value is invalid")
	}
	var session webAuthnSigninSession
	if err := util.JsonToStruct(serialized, &session); err != nil {
		return webAuthnSigninSession{}, fmt.Errorf("decode WebAuthn authentication session: %w", err)
	}
	if err := session.validate(time.Now()); err != nil {
		return webAuthnSigninSession{}, err
	}
	if !claimWebAuthnSigninTransaction(session.TransactionId, session.Ceremony.Expires.Unix(), time.Now().Unix()) {
		return webAuthnSigninSession{}, fmt.Errorf("WebAuthn authentication challenge has already been consumed")
	}
	return session, nil
}

// WebAuthnSignupBegin
// @Title WebAuthnSignupBegin
// @Tag User API
// @Description WebAuthn Registration Flow 1st stage
// @Success 200 {object} protocol.CredentialCreation The CredentialCreationOptions object
// @router /webauthn/signup/begin [get]
func (c *ApiController) WebAuthnSignupBegin() {
	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	user := c.getCurrentUser()
	if user == nil {
		c.ResponseError(c.T("general:Please login first"))
		return
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
		credCreationOpts.AuthenticatorSelection.ResidentKey = "preferred"
		credCreationOpts.Attestation = "none"

		ext := map[string]interface{}{
			"credProps": true,
		}
		credCreationOpts.Extensions = ext
	}
	options, sessionData, err := webauthnObj.BeginRegistration(
		user,
		registerOptions,
	)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.SetSession("registration", *sessionData)
	c.Data["json"] = options
	c.ServeJSON()
}

// WebAuthnSignupFinish
// @Title WebAuthnSignupFinish
// @Tag User API
// @Description WebAuthn Registration Flow 2nd stage
// @Param   body    body   protocol.CredentialCreationResponse  true        "authenticator attestation Response"
// @Success 200 {object} controllers.Response "The Response object"
// @router /webauthn/signup/finish [post]
func (c *ApiController) WebAuthnSignupFinish() {
	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	user := c.getCurrentUser()
	if user == nil {
		c.ResponseError(c.T("general:Please login first"))
		return
	}
	sessionObj := c.GetSession("registration")
	sessionData, ok := sessionObj.(webauthn.SessionData)
	if !ok {
		c.ResponseError(c.T("webauthn:Please call WebAuthnSigninBegin first"))
		return
	}
	c.Ctx.Request.Body = io.NopCloser(bytes.NewBuffer(c.Ctx.Input.RequestBody))

	credential, err := webauthnObj.FinishRegistration(user, sessionData, c.Ctx.Request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	isGlobalAdmin := c.IsGlobalAdmin()
	_, err = user.AddCredentials(*credential, isGlobalAdmin)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk()
}

// WebAuthnSigninBegin
// @Title WebAuthnSigninBegin
// @Tag Login API
// @Description WebAuthn Login Flow 1st stage
// @Param   owner     query    string  true        "owner"
// @Param   name     query    string  true        "name"
// @Success 200 {object} protocol.CredentialAssertion The CredentialAssertion object
// @router /webauthn/signin/begin [get]
func (c *ApiController) WebAuthnSigninBegin() {
	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	responseType := c.getQueryValue("responseType", "response_type")
	if responseType == "" {
		responseType = ResponseTypeLogin
	}
	var authorizationRequest *object.AuthorizationRequest
	if responseType == ResponseTypeCode {
		request, requestErr := c.captureAuthorizationRequest()
		if requestErr != nil {
			c.ResponseError(requestErr.Error())
			return
		}
		authorizationRequest = &request
	}

	userOwner := c.Ctx.Input.Query("owner")
	userName := c.Ctx.Input.Query("name")

	var options *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData

	if userName == "" {
		options, sessionData, err = webauthnObj.BeginDiscoverableLogin()
	} else {
		var user *object.User
		user, err = object.GetUserByFields(userOwner, userName)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if user == nil {
			c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(userOwner, userName)))
			return
		}
		if len(user.WebauthnCredentials) == 0 {
			c.ResponseError(c.T("webauthn:Found no credentials for this user"))
			return
		}

		options, sessionData, err = webauthnObj.BeginLogin(user)
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	boundSession, err := newWebAuthnSigninSession(*sessionData, responseType, authorizationRequest)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	serializedSession, err := json.Marshal(boundSession)
	if err != nil {
		c.ResponseError(fmt.Sprintf("encode WebAuthn authentication session: %v", err))
		return
	}
	// A newly created ceremony supersedes every older authentication
	// transaction carried by this browser session.
	if err = c.clearCurrentAuthenticationContext(); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if err = c.clearPendingAuthentication(); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if err = c.SetSession(webAuthnAuthenticationSessionKey, string(serializedSession)); err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Data["json"] = options
	c.ServeJSON()
}

// WebAuthnSigninFinish
// @Title WebAuthnSigninFinish
// @Tag Login API
// @Description WebAuthn Login Flow 2nd stage
// @Param   body    body   protocol.CredentialAssertionResponse  true        "authenticator assertion Response"
// @Success 200 {object} controllers.Response "The Response object"
// @router /webauthn/signin/finish [post]
func (c *ApiController) WebAuthnSigninFinish() {
	boundSession, err := c.consumeWebAuthnSigninSession()
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	responseType := c.getQueryValue("responseType", "response_type")
	if responseType == "" {
		responseType = ResponseTypeLogin
	}
	var authorizationRequest *object.AuthorizationRequest
	if responseType == ResponseTypeCode {
		request, requestErr := c.captureAuthorizationRequest()
		if requestErr != nil {
			c.ResponseError(requestErr.Error())
			return
		}
		authorizationRequest = &request
	}
	if err = boundSession.matchesContinuation(responseType, authorizationRequest); err != nil {
		c.ResponseError(err.Error())
		return
	}

	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	sessionData := boundSession.Ceremony
	c.Ctx.Request.Body = io.NopCloser(bytes.NewBuffer(c.Ctx.Input.RequestBody))

	var user *object.User
	if sessionData.UserID != nil {
		userId := string(sessionData.UserID)
		user, err = object.GetUser(userId)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		_, err = webauthnObj.FinishLogin(user, sessionData, c.Ctx.Request)
	} else {
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			user, err = object.GetUserByWebauthID(base64.StdEncoding.EncodeToString(rawID))
			if err != nil {
				return nil, err
			}
			return user, nil
		}

		_, err = webauthnObj.FinishDiscoverableLogin(handler, sessionData, c.Ctx.Request)
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("WebAuthn authenticated user is missing")
		return
	}

	var application *object.Application

	if authorizationRequest != nil {
		application, err = object.GetApplicationByClientId(authorizationRequest.ClientId)
	} else {
		application, err = object.GetApplicationByUser(user)
	}
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError(c.T("check:Application does not exist"))
		return
	}

	authenticationContext, contextErr := c.beginAuthentication(user, []string{"webauthn"}, "", responseType, application, "")
	if contextErr != nil {
		c.ResponseError(contextErr.Error())
		return
	}
	organization, organizationErr := object.GetOrganizationByUser(user)
	if organizationErr != nil {
		c.ResponseError(organizationErr.Error())
		return
	}
	if organization == nil {
		c.ResponseError("organization does not exist")
		return
	}
	if checkMfaEnable(c, user, organization, "webauthn") {
		return
	}
	if contextErr = c.completeAuthentication(authenticationContext); contextErr != nil {
		_ = c.clearPendingAuthentication()
		c.ResponseError(contextErr.Error())
		return
	}
	util.LogInfo(c.Ctx, "API: [%s] signed in", user.GetId())

	var authForm form.AuthForm
	authForm.Type = responseType
	resp := c.HandleLoggedIn(application, user, &authForm)
	c.Data["json"] = resp
	c.ServeJSON()
}
