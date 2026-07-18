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
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/captcha"
	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/casdoor/casdoor/util"
	"golang.org/x/oauth2"
)

const mfaRestartLoginMessage = "MFA session is missing or expired; restart sign-in"

func codeToResponse(code *object.Code) *Response {
	if code.Code == "" {
		return &Response{Status: "error", Msg: code.Message, Data: code.Code}
	}

	return &Response{Status: "ok", Msg: "", Data: code.Code}
}

func tokenToResponse(token *object.Token) *Response {
	if token.AccessToken == "" {
		return &Response{Status: "error", Msg: "fail to get accessToken", Data: token.AccessToken}
	}
	return &Response{Status: "ok", Msg: "", Data: token.AccessToken, Data2: token.RefreshToken}
}

// validateAuthenticatedApplicationAccess contains the authorization gates that
// must hold both immediately after primary authentication and again after a
// delayed MFA enrollment. It intentionally performs no token/code issuance or
// username-session promotion.
func (c *ApiController) validateAuthenticatedApplicationAccess(application *object.Application, user *object.User) bool {
	if application == nil || user == nil {
		c.ResponseError("authenticated user or application is missing")
		return false
	}
	if user.IsForbidden {
		c.ResponseError(c.T("check:The user is forbidden to sign in, please contact the administrator"))
		return false
	}
	if user.IsDeleted {
		c.ResponseError(c.T("check:The user has been deleted and cannot be used to sign in, please contact the administrator"))
		return false
	}

	userId := user.GetId()
	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)
	if err := object.CheckEntryIp(clientIp, user, application, application.OrganizationObj, c.GetAcceptLanguage()); err != nil {
		c.ResponseError(err.Error())
		return false
	}
	if application.DisableSignin {
		c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s has disabled users to signin"), application.Name))
		return false
	}
	if application.OrganizationObj != nil && application.OrganizationObj.DisableSignin {
		c.ResponseError(fmt.Sprintf(c.T("auth:The organization: %s has disabled users to signin"), application.Organization))
		return false
	}
	allowed, err := object.CheckLoginPermission(userId, application)
	if err != nil {
		c.ResponseError(err.Error(), nil)
		return false
	}
	if !allowed {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return false
	}
	if !user.IsGlobalAdmin() && !user.IsAdmin && len(application.Tags) > 0 && !util.HasTagInSlice(application.Tags, user.Tag) {
		c.ResponseError(fmt.Sprintf(c.T("auth:User's tag: %s is not listed in the application's tags"), user.Tag))
		return false
	}

	if user.Type == "paid-user" {
		subscriptions, err := object.GetSubscriptionsByUser(user.Owner, user.Name)
		if err != nil {
			c.ResponseError(err.Error())
			return false
		}
		for _, subscription := range subscriptions {
			if subscription.State == object.SubStateActive {
				return true
			}
		}
		for _, subscription := range subscriptions {
			if subscription.State == object.SubStatePending {
				c.ResponseOk("BuyPlanResult", subscription)
				return false
			}
		}
		pricing, err := object.GetApplicationDefaultPricing(application.Organization, application.Name)
		if err != nil {
			c.ResponseError(err.Error())
			return false
		}
		if pricing == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:paid-user %s does not have active or pending subscription and the application: %s does not have default pricing"), user.Name, application.Name))
			return false
		}
		c.SetSession("paidUsername", user.GetId())
		c.ResponseOk("SelectPlan", pricing)
		return false
	}
	return true
}

// HandleLoggedIn ...
func (c *ApiController) HandleLoggedIn(application *object.Application, user *object.User, form *form.AuthForm) (resp *Response) {
	defer func() {
		if resp == nil || resp.Status != "ok" {
			c.clearPendingAuthentication()
		}
	}()

	if !c.validateAuthenticatedApplicationAccess(application, user) {
		return
	}
	userId := user.GetId()

	if form.Type == ResponseTypeLogin {
		c.SetSessionUsername(userId)
		util.LogInfo(c.Ctx, "API: [%s] signed in", userId)
		resp = &Response{Status: "ok", Msg: "", Data: userId, Data3: user.NeedUpdatePassword}
	} else if form.Type == ResponseTypeCode {
		authenticationContext, err := c.getCurrentAuthenticationContext()
		if err != nil {
			if isMfaContinuationSubmission(form) {
				c.ResponseError(mfaRestartLoginMessage)
				return
			}
			c.ResponseError(fmt.Sprintf("authentication context is required: %s", err.Error()))
			return
		}

		authorizationRequest, err := c.captureAuthorizationRequest()
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		pending, pendingErr := c.getPendingAuthentication()
		if pendingErr != nil {
			if isMfaContinuationSubmission(form) {
				c.ResponseError(mfaRestartLoginMessage)
				return
			}
			c.ResponseError(fmt.Sprintf("pending authentication is required: %s", pendingErr.Error()))
			return
		}
		if pending.Context.Subject != userId || !pending.Context.Equal(authenticationContext) {
			c.ResponseError("pending authentication does not match signed-in authentication context")
			return
		}
		if pending.FlowType != ResponseTypeCode || pending.ApplicationId != application.GetId() {
			c.ResponseError("pending authentication does not match OAuth application flow")
			return
		}
		if pending.Request == nil {
			c.ResponseError("pending OAuth authorization request is missing")
			return
		}
		if !authorizationRequest.Equal(*pending.Request) {
			c.ResponseError("OAuth authorization request does not match pending authentication")
			return
		}
		authenticationContext = pending.Context
		authorizationRequest = pending.Request.Clone()
		if application.ClientId != authorizationRequest.ClientId {
			c.ResponseError("OAuth client does not match the authenticated application")
			return
		}

		consentRequired, err := object.CheckConsentRequired(user, application, authorizationRequest.Scope)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		prompts, err := authorizationRequest.PromptValues()
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if slices.Contains(prompts, "consent") {
			consentRequired = true
		}

		needSigninSession := application.EnableSigninSession || application.HasPromptPage() || consentRequired
		if needSigninSession {
			// Prompt and consent pages need the user to be signed in.
			c.SetSessionUsername(userId)
		}

		if consentRequired {
			resp = &Response{Status: "ok", Data: map[string]bool{"required": true}}
			resp.Data3 = user.NeedUpdatePassword
		} else {
			if err = c.consumePendingAuthentication(pending.TransactionId, pending.ExpiresAt); err != nil {
				if isMfaContinuationSubmission(form) {
					c.ResponseError(mfaRestartLoginMessage)
					return
				}
				c.ResponseError("authentication transaction is missing, expired, or already consumed")
				return
			}
			code, err := object.GetOAuthCodeWithAuthenticationContext(
				userId,
				authorizationRequest.ClientId,
				authenticationContext,
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
				c.ResponseError(err.Error(), nil)
				return
			}

			resp = codeToResponse(code)
			resp.Data3 = user.NeedUpdatePassword
		}
	} else if form.Type == ResponseTypeToken || form.Type == ResponseTypeIdToken { // implicit flow
		if !object.IsGrantTypeValid(form.Type, application.GrantTypes) {
			resp = &Response{Status: "error", Msg: fmt.Sprintf("error: grant_type: %s is not supported in this application", form.Type), Data: ""}
		} else {
			scope := c.Ctx.Input.Query("scope")
			nonce := c.Ctx.Input.Query("nonce")
			if nonceError := object.ValidateOAuthNonceForGrant(form.Type, nonce); nonceError != nil {
				resp = &Response{Status: "error", Msg: nonceError.ErrorDescription, Data: ""}
				return
			}
			expandedScope, valid := object.IsScopeValidAndExpand(scope, application)
			if !valid {
				resp = &Response{Status: "error", Msg: "error: invalid_scope", Data: ""}
			} else {
				authenticationContext, contextErr := c.getCurrentAuthenticationContext()
				if contextErr != nil || authenticationContext.Subject != userId {
					resp = &Response{Status: "error", Msg: "error: verified authentication context is required", Data: ""}
					return
				}
				token, tokenErr := object.GetTokenByUserForGrantWithAuthenticationContext(application, user, form.Type, expandedScope, nonce, c.Ctx.Request.Host, authenticationContext)
				if tokenErr != nil {
					resp = &Response{Status: "error", Msg: tokenErr.Error(), Data: ""}
					return
				}
				resp = tokenToResponse(token)

				resp.Data3 = user.NeedUpdatePassword
			}
		}
	} else if form.Type == ResponseTypeDevice {
		pendingUserCodeCache, ok := object.DeviceAuthMap.Load(form.UserCode)
		if !ok {
			c.ResponseError(c.T("auth:UserCode Expired"))
			return
		}
		pendingUserCodeCacheCast, ok := pendingUserCodeCache.(object.DeviceAuthCache)
		if !ok || pendingUserCodeCacheCast.ApplicationId != application.GetId() || pendingUserCodeCacheCast.ClientId != application.ClientId {
			c.ResponseError(c.T("auth:The application does not match the device authorization request"))
			return
		}

		authCache, ok := object.DeviceAuthMap.LoadAndDelete(form.UserCode)
		if !ok {
			c.ResponseError(c.T("auth:UserCode Expired"))
			return
		}

		authCacheCast, ok := authCache.(object.DeviceAuthCache)
		if !ok || authCacheCast.ApplicationId != application.GetId() || authCacheCast.ClientId != application.ClientId {
			c.ResponseError(c.T("auth:The application does not match the device authorization request"))
			return
		}
		if authCacheCast.Status == object.DeviceAuthStatusDenied {
			if authCacheCast.UserName != "" {
				object.DeviceAuthMap.Delete(authCacheCast.UserName)
			}
			c.ResponseError(c.T("auth:DeviceCode Invalid"))
			return
		}

		expiresIn := authCacheCast.ExpiresIn
		if expiresIn == 0 {
			expiresIn = object.DeviceAuthExpiresIn
		}
		if authCacheCast.RequestAt.Add(time.Duration(expiresIn) * time.Second).Before(time.Now()) {
			if authCacheCast.UserName != "" {
				object.DeviceAuthMap.Delete(authCacheCast.UserName)
			}
			c.ResponseError(c.T("auth:UserCode Expired"))
			return
		}

		deviceAuthCacheDeviceCode, ok := object.DeviceAuthMap.Load(authCacheCast.UserName)
		if !ok {
			c.ResponseError(c.T("auth:DeviceCode Invalid"))
			return
		}

		deviceAuthCacheDeviceCodeCast, ok := deviceAuthCacheDeviceCode.(object.DeviceAuthCache)
		if !ok ||
			deviceAuthCacheDeviceCodeCast.ApplicationId != application.GetId() ||
			deviceAuthCacheDeviceCodeCast.ClientId != application.ClientId ||
			deviceAuthCacheDeviceCodeCast.ApplicationId != authCacheCast.ApplicationId ||
			deviceAuthCacheDeviceCodeCast.ClientId != authCacheCast.ClientId {
			c.ResponseError(c.T("auth:The application does not match the device authorization request"))
			return
		}
		deviceAuthCacheDeviceCodeCast.UserName = user.Name
		deviceAuthCacheDeviceCodeCast.UserSignIn = true
		deviceAuthCacheDeviceCodeCast.Status = object.DeviceAuthStatusApproved
		authenticationContext, contextErr := c.getCurrentAuthenticationContext()
		if contextErr != nil || authenticationContext.Subject != userId {
			c.ResponseError("verified authentication context is required for device authorization")
			return
		}
		deviceAuthCacheDeviceCodeCast.AuthenticationContext = authenticationContext

		object.DeviceAuthMap.Store(authCacheCast.UserName, deviceAuthCacheDeviceCodeCast)

		resp = &Response{Status: "ok", Msg: "", Data: userId, Data3: user.NeedUpdatePassword}
	} else if form.Type == ResponseTypeSaml { // saml flow
		res, redirectUrl, method, err := object.GetSamlResponse(application, user, form.SamlRequest, c.Ctx.Request.Host)
		if err != nil {
			c.ResponseError(err.Error(), nil)
			return
		}
		resp = &Response{Status: "ok", Msg: "", Data: res, Data2: map[string]interface{}{"redirectUrl": redirectUrl, "method": method}, Data3: user.NeedUpdatePassword}

		if application.EnableSigninSession || application.HasPromptPage() {
			// The prompt page needs the user to be signed in
			c.SetSessionUsername(userId)
		}
	} else if form.Type == ResponseTypeCas {
		// not oauth but CAS SSO protocol
		service := c.Ctx.Input.Query("service")
		resp = wrapErrorResponse(nil)
		if service != "" {
			st, err := object.GenerateCasToken(userId, service)
			if err != nil {
				resp = wrapErrorResponse(err)
			} else {
				resp.Data = st
			}
		}

		if application.EnableSigninSession || application.HasPromptPage() {
			// The prompt page needs the user to be signed in
			c.SetSessionUsername(userId)
		}
	} else {
		resp = wrapErrorResponse(fmt.Errorf("unknown response type: %s", form.Type))
	}

	// For all successful logins, set the session expiration; if auto signin is not checked, cap it at 24 hours.
	if resp.Status == "ok" {
		if form.Type != ResponseTypeCode {
			c.clearPendingAuthentication()
		}
		expireInHours := application.CookieExpireInHours

		if expireInHours == 0 {
			expireInHours = 720
		}

		if !form.AutoSignin && expireInHours > 24 {
			expireInHours = 24
		}
		c.setExpireForSession(expireInHours)
	}

	if resp.Status == "ok" {
		if application.EnableExclusiveSignin {
			sessions, err := object.GetUserAppSessions(user.Owner, user.Name, application.Name)
			if err != nil {
				c.ResponseError(err.Error(), nil)
				return
			}

			for _, session := range sessions {
				for _, sid := range session.SessionId {
					err := web.GlobalSessions.GetProvider().SessionDestroy(context.Background(), sid)
					if err != nil {
						c.ResponseError(err.Error(), nil)
						return
					}
				}
			}
		}

		_, err := object.AddSession(&object.Session{
			Owner:       user.Owner,
			Name:        user.Name,
			Application: application.Name,
			SessionId:   []string{c.Ctx.Input.CruSession.SessionID(context.Background())},

			ExclusiveSignin: application.EnableExclusiveSignin,
		})
		if err != nil {
			c.ResponseError(err.Error(), nil)
			return
		}
	}

	return resp
}

// GetApplicationLogin ...
// @Title GetApplicationLogin
// @Tag Login API
// @Description get application login
// @Param   clientId    query    string  true        "client id"
// @Param   responseType    query    string  true        "response type"
// @Param   redirectUri    query    string  true        "redirect uri"
// @Param   scope    query    string  true        "scope"
// @Param   state    query    string  true        "state"
// @Success 200 {object} controllers.Response The Response object
// @router /get-app-login [get]
func (c *ApiController) GetApplicationLogin() {
	clientId := c.Ctx.Input.Query("clientId")
	responseType := c.Ctx.Input.Query("responseType")
	redirectUri := c.Ctx.Input.Query("redirectUri")
	scope := c.Ctx.Input.Query("scope")
	state := c.Ctx.Input.Query("state")
	id := c.Ctx.Input.Query("id")
	loginType := c.Ctx.Input.Query("type")
	userCode := c.Ctx.Input.Query("userCode")

	var application *object.Application
	var msg string
	var err error
	if loginType == "code" {
		msg, application, err = object.CheckOAuthLogin(clientId, responseType, redirectUri, scope, state, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	} else if loginType == "cas" {
		application, err = object.GetApplication(id)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if application == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), id))
			return
		}

		err = object.CheckCasLogin(application, c.GetAcceptLanguage(), redirectUri)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	} else if loginType == "device" {
		deviceAuthCache, ok := object.DeviceAuthMap.Load(userCode)
		if !ok {
			c.ResponseError(c.T("auth:UserCode Invalid"))
			return
		}

		deviceAuthCacheCast := deviceAuthCache.(object.DeviceAuthCache)
		application, err = object.GetApplication(deviceAuthCacheCast.ApplicationId)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)
	object.CheckEntryIp(clientIp, nil, application, nil, c.GetAcceptLanguage())

	application = object.GetMaskedApplication(application, "")
	if err = c.attachProviderStates(application); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if msg != "" {
		c.ResponseError(msg, application)
	} else {
		c.ResponseOk(application)
	}
}

func setHttpClient(idProvider idp.IdProvider, provider *object.Provider) {
	if provider.EnableProxy || isProxyProviderType(provider.Type) {
		idProvider.SetHttpClient(proxy.ProxyHttpClient)
	} else {
		idProvider.SetHttpClient(proxy.DefaultHttpClient)
	}
}

func isProxyProviderType(providerType string) bool {
	providerTypes := []string{
		"GitHub",
		"Google",
		"Facebook",
		"LinkedIn",
		"Steam",
		"Line",
		"Amazon",
		"Instagram",
		"TikTok",
		"Twitter",
		"Uber",
		"Yahoo",
	}
	for _, v := range providerTypes {
		if strings.EqualFold(v, providerType) {
			return true
		}
	}
	return false
}

func isSupportedMfaAuthenticationType(mfaType string) bool {
	// TOTP is locally verified and RADIUS uses a server-stored provider binding.
	// SMS/email verification records are not purpose-bound or atomically
	// consumed, and Push has no verifiable approval callback yet.
	return mfaType == object.TotpType || mfaType == object.RadiusType
}

func getMissingRequiredMfaTypes(organization *object.Organization, user *object.User) []string {
	if organization == nil || user == nil {
		return nil
	}
	items := organization.MfaItems
	if len(user.MfaItems) > 0 {
		items = user.MfaItems
	}
	res := []string{}
	for _, item := range items {
		if item != nil && object.IsRequiredMfaType(organization, user, item.Name) && !slices.Contains(res, item.Name) {
			res = append(res, item.Name)
		}
	}
	return res
}

func checkMfaEnable(c *ApiController, user *object.User, organization *object.Organization, verificationType string) bool {
	if object.IsNeedPromptMfa(organization, user) {
		pending, err := c.getPendingAuthentication()
		if err != nil {
			c.ResponseError(err.Error())
			return true
		}
		if pending.FlowType != ResponseTypeLogin && pending.FlowType != ResponseTypeCode {
			c.ClearUserSession()
			c.ResponseError("Required MFA enrollment supports login and authorization-code flows only; authenticate again after enrollment")
			return true
		}
		for _, requiredType := range getMissingRequiredMfaTypes(organization, user) {
			if !isSupportedMfaSetupType(requiredType) {
				c.ClearUserSession()
				c.ResponseError(fmt.Sprintf("Required MFA type %q is not supported by the hardened enrollment flow; an administrator must migrate the policy to TOTP", requiredType))
				return true
			}
		}
		// Required MFA enrollment is an authentication continuation, not a
		// signed-in Casdoor session. Only the MFA setup endpoints may use this
		// restricted identity until enrollment has been verified and promoted.
		if err := c.SessionRegenerateID(); err != nil {
			c.ResponseError(fmt.Sprintf("regenerate MFA setup session: %s", err.Error()))
			return true
		}
		if err := c.SetSession("username", ""); err != nil {
			c.ResponseError(err.Error())
			return true
		}
		if err := c.setMfaUserSession(""); err != nil {
			c.ResponseError(err.Error())
			return true
		}
		if err := c.setMfaSetupUserSession(user.GetId()); err != nil {
			c.ResponseError(err.Error())
			return true
		}
		c.Ctx.Input.CruSession.SessionRelease(context.Background(), c.Ctx.ResponseWriter)
		c.ResponseOk(object.RequiredMfa)
		return true
	}

	if user.IsMfaEnabled() {
		mfaList := object.GetAllMfaProps(user, true)
		mfaAllowList := []*object.MfaProps{}
		mfaRememberInHours := organization.MfaRememberInHours
		hasEnabledFactor := false
		for _, prop := range mfaList {
			if !prop.Enabled {
				continue
			}
			hasEnabledFactor = true
			if prop.MfaType == verificationType || !isSupportedMfaAuthenticationType(prop.MfaType) {
				continue
			}
			prop.MfaRememberInHours = mfaRememberInHours
			mfaAllowList = append(mfaAllowList, prop)
		}
		if len(mfaAllowList) >= 1 {
			if err := c.setMfaUserSession(user.GetId()); err != nil {
				c.ResponseError(err.Error())
				return true
			}
			if err := c.SetSession("verificationCodeType", verificationType); err != nil {
				c.ResponseError(err.Error())
				return true
			}
			c.Ctx.Input.CruSession.SessionRelease(context.Background(), c.Ctx.ResponseWriter)
			c.ResponseOk(object.NextMfa, mfaAllowList)
			return true
		}
		if hasEnabledFactor {
			c.ResponseError("An independent TOTP or administrator-provisioned RADIUS factor is required")
			return true
		}
	}

	return false
}

func getExistUserByBindingRule(providerItem *object.ProviderItem, application *object.Application, userInfo *idp.UserInfo) (user *object.User, err error) {
	if providerItem.BindingRule == nil {
		providerItem.BindingRule = &[]string{"Email", "Phone", "Name"}
	}
	if len(*providerItem.BindingRule) == 0 {
		return nil, nil
	}

	for _, rule := range *providerItem.BindingRule {
		// Find existing user with Email
		if rule == "Email" {
			user, err = object.GetUserByField(application.Organization, "email", userInfo.Email)
			if err != nil {
				return nil, err
			}
			if user != nil {
				return user, nil
			}
		}

		// Find existing user with phone number
		if rule == "Phone" {
			user, err = object.GetUserByField(application.Organization, "phone", userInfo.Phone)
			if err != nil {
				return nil, err
			}
			if user != nil {
				return user, nil
			}
		}

		// Try to find existing user by username (case-insensitive)
		// This allows OAuth providers (e.g., Wecom) to automatically associate with
		// existing users when usernames match, particularly useful for enterprise
		// scenarios where signup is disabled and users already exist in Casdoor
		if rule == "Name" {
			user, err = object.GetUserByFields(application.Organization, userInfo.Username)
			if err != nil {
				return nil, err
			}
			if user != nil {
				return user, nil
			}
		}
	}

	return user, nil
}

func getUserByProvider(organization string, provider *object.Provider, providerId string) (*object.User, error) {
	if object.IsFlexibleCustomProvider(provider.Type) {
		return object.GetUserByThirdPartyLink(organization, provider.Name, providerId)
	}
	if provider.Category == "SAML" {
		return object.GetUserByFields(organization, providerId)
	}
	return object.GetUserByField(organization, provider.Type, providerId)
}

func linkUserByProvider(user *object.User, provider *object.Provider, providerId string) (bool, error) {
	if object.IsFlexibleCustomProvider(provider.Type) {
		return object.LinkFlexibleCustomAccount(user, provider.Name, providerId)
	}
	return object.LinkUserAccount(user, provider.Type, providerId)
}

func resolvePasswordSigninMethod(application *object.Application, signinMethod string) (isSigninViaLdap bool, isPasswordWithLdapEnabled bool, err error) {
	if application == nil {
		return false, false, fmt.Errorf("application is missing")
	}

	switch signinMethod {
	case "":
		// Older Casdoor clients omit the selector for local password login. Keep
		// that wire format compatible, but still require password authentication
		// to be enabled explicitly. Unlike "Password", the legacy path must not
		// silently add LDAP fallback; this preserves the pre-hardening behavior.
		if !application.IsPasswordEnabled() {
			return false, false, fmt.Errorf("the login method: login with password is not enabled for the application")
		}
		return false, false, nil
	case "Password":
		if !application.IsPasswordEnabled() {
			return false, false, fmt.Errorf("the login method: login with password is not enabled for the application")
		}
		return false, application.IsPasswordWithLdapEnabled(), nil
	case "LDAP":
		if !application.IsLdapEnabled() {
			return false, false, fmt.Errorf("the login method: login with LDAP is not enabled for the application")
		}
		return true, false, nil
	default:
		// A non-empty password is a credential, not a method selector. Requiring
		// an exact known method prevents unknown values (notably from
		// machine-to-machine clients) from falling through to local password
		// verification.
		return false, false, fmt.Errorf("the login method is invalid for password authentication")
	}
}

// Login ...
// @Title Login
// @Tag Login API
// @Description login
// @Param clientId        query    string  true clientId
// @Param responseType    query    string  true responseType
// @Param redirectUri     query    string  true redirectUri
// @Param scope     query    string  false  scope
// @Param state     query    string  false  state
// @Param nonce     query    string  false nonce
// @Param code_challenge_method   query    string  false code_challenge_method
// @Param code_challenge          query    string  false code_challenge
// @Param   form   body   form.AuthForm  true        "Login information"
// @Success 200 {object} controllers.Response The Response object
// @router /login [post]
func (c *ApiController) Login() {
	resp := &Response{}

	var authForm form.AuthForm
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &authForm)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	verificationType := ""

	if authForm.Username != "" {
		var user *object.User
		var authenticationMethods []string
		if authForm.SigninMethod == "Face ID" {
			var application *object.Application
			application, err = object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				c.ResponseError(err.Error(), nil)
				return
			}

			if application == nil {
				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}

			if user, err = object.GetUserByFieldsForSharedApp(application, authForm.Organization, authForm.Username); err != nil {
				c.ResponseError(err.Error(), nil)
				return
			} else if user == nil {
				c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(authForm.Organization, authForm.Username)))
				return
			}

			if !application.IsFaceIdEnabled() {
				c.ResponseError(c.T("auth:The login method: login with face is not enabled for the application"))
				return
			}

			faceIdProvider, err := object.GetFaceIdProviderByApplication(util.GetId(application.Owner, application.Name), "false", c.GetAcceptLanguage())
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if faceIdProvider == nil {
				if err := object.CheckFaceId(user, authForm.FaceId, c.GetAcceptLanguage()); err != nil {
					c.ResponseError(err.Error(), nil)
					return
				}
			} else {
				if !user.HasFaceIdImage() {
					c.ResponseError(i18n.Translate(c.GetAcceptLanguage(), "check:Face data does not exist, cannot log in"))
					return
				}

				ok, err := user.CheckUserFace(authForm.FaceIdImage, faceIdProvider)
				if err != nil {
					c.ResponseError(err.Error(), nil)
					return
				}

				if !ok {
					c.ResponseError(i18n.Translate(c.GetAcceptLanguage(), "check:Face data mismatch"))
					return
				}
			}
			authenticationMethods = []string{"face"}
		} else if authForm.Password == "" {
			var application *object.Application
			application, err = object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				c.ResponseError(err.Error(), nil)
				return
			}

			if application == nil {
				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}

			// If the username looks like a phone number and a countryCode is provided,
			// normalise it to E.164 format before looking up the user so that users
			// from different countries sharing the same local number are distinguished.
			lookupUsername := authForm.Username
			if !strings.Contains(authForm.Username, "@") && authForm.CountryCode != "" {
				if e164, ok := util.GetE164Number(authForm.Username, authForm.CountryCode); ok {
					lookupUsername = e164
				}
			}

			if user, err = object.GetUserByFieldsForSharedApp(application, authForm.Organization, lookupUsername); err != nil {
				c.ResponseError(err.Error(), nil)
				return
			} else if user == nil {
				c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(authForm.Organization, authForm.Username)))
				return
			}

			verificationCodeType := object.GetVerifyType(authForm.Username)
			if verificationCodeType == object.VerifyTypeEmail && !application.IsCodeSigninViaEmailEnabled() {
				c.ResponseError(c.T("auth:The login method: login with email is not enabled for the application"))
				return
			}
			if verificationCodeType == object.VerifyTypePhone && !application.IsCodeSigninViaSmsEnabled() {
				c.ResponseError(c.T("auth:The login method: login with SMS is not enabled for the application"))
				return
			}

			var checkDest string
			if verificationCodeType == object.VerifyTypePhone {
				authForm.CountryCode = user.GetCountryCode(authForm.CountryCode)
				var ok bool
				if checkDest, ok = util.GetE164Number(authForm.Username, authForm.CountryCode); !ok {
					c.ResponseError(fmt.Sprintf(c.T("verification:Phone number is invalid in your region %s"), authForm.CountryCode))
					return
				}
			} else if verificationCodeType == object.VerifyTypeEmail {
				checkDest = authForm.Username
			}

			// check result through Email or Phone
			err = object.CheckSigninCode(user, checkDest, authForm.Code, c.GetAcceptLanguage())
			if err != nil {
				c.ResponseError(fmt.Sprintf("%s - %s", verificationCodeType, err.Error()))
				return
			}

			// disable the verification code
			err = object.DisableVerificationCode(checkDest)
			if err != nil {
				c.ResponseError(err.Error(), nil)
				return
			}

			if verificationCodeType == object.VerifyTypePhone {
				verificationType = "sms"
			} else {
				verificationType = "email"
				if !user.EmailVerified {
					user.EmailVerified = true
					_, err = object.UpdateUser(user.GetId(), user, []string{"email_verified"}, false)
					if err != nil {
						c.ResponseError(err.Error(), nil)
						return
					}
				}
			}
			authenticationMethods = []string{verificationType}
		} else {
			var application *object.Application
			application, err = object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				c.ResponseError(err.Error(), nil)
				return
			}

			if application == nil {
				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}
			isSigninViaLdap, isPasswordWithLdapEnabled, methodErr := resolvePasswordSigninMethod(application, authForm.SigninMethod)
			if methodErr != nil {
				c.ResponseError(c.T(methodErr.Error()))
				return
			}

			clientIp := util.GetClientIpFromRequest(c.Ctx.Request)

			var enableCaptcha bool
			if enableCaptcha, err = object.CheckToEnableCaptcha(application, authForm.Organization, authForm.Username, clientIp); err != nil {
				c.ResponseError(err.Error())
				return
			} else if enableCaptcha {
				captchaProvider, err := object.GetCaptchaProviderByApplication(util.GetId(application.Owner, application.Name), "false", c.GetAcceptLanguage())
				if err != nil {
					c.ResponseError(err.Error())
					return
				}

				if captchaProvider.Type != "Default" {
					authForm.ClientSecret = captchaProvider.ClientSecret
				}

				var isHuman bool
				isHuman, err = captcha.VerifyCaptchaByCaptchaType(authForm.CaptchaType, authForm.CaptchaToken, captchaProvider.ClientId, authForm.ClientSecret, captchaProvider.ClientId2)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}

				if !isHuman {
					c.ResponseError(c.T("verification:Turing test failed."))
					return
				}
			}

			password := authForm.Password

			if application.OrganizationObj != nil {
				password, err = util.GetUnobfuscatedPassword(application.OrganizationObj.PasswordObfuscatorType, application.OrganizationObj.PasswordObfuscatorKey, authForm.Password)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}
			}

			if application.IsShared {
				var resolvedUser *object.User
				resolvedUser, err = object.GetUserByFieldsForSharedApp(application, authForm.Organization, authForm.Username)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}
				if resolvedUser != nil {
					authForm.Organization = resolvedUser.Owner
				}
			}

			user, err = object.CheckUserPassword(authForm.Organization, authForm.Username, password, c.GetAcceptLanguage(), enableCaptcha, isSigninViaLdap, isPasswordWithLdapEnabled)
			if err == nil {
				authenticationMethods, err = object.GetVerifiedPasswordAuthenticationMethods(user, password)
			}
		}

		if err != nil {
			var signinErr *object.SigninError
			if errors.As(err, &signinErr) {
				c.Ctx.Input.SetParam("recordDetail", signinErr.Reason)
			}
			c.ResponseError(err.Error())
			return
		} else {
			var application *object.Application
			application, err = object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if application == nil {
				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}

			authenticationContext, contextErr := c.beginAuthentication(user, authenticationMethods, "", authForm.Type, application, authForm.UserCode)
			if contextErr != nil {
				c.ResponseError(contextErr.Error())
				return
			}

			var organization *object.Organization
			organization, err = object.GetOrganizationByUser(user)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			if organization == nil {
				c.ResponseError("organization does not exist")
				return
			}

			if checkMfaEnable(c, user, organization, verificationType) {
				return
			}

			if contextErr = c.completeAuthentication(authenticationContext); contextErr != nil {
				c.ResponseError(contextErr.Error())
				return
			}

			resp = c.HandleLoggedIn(application, user, &authForm)

			c.Ctx.Input.SetParam("recordUserId", user.GetId())
		}
	} else if authForm.Provider != "" {
		var application *object.Application
		if authForm.ClientId != "" {
			application, err = object.GetApplicationByClientId(authForm.ClientId)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		} else {
			application, err = object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		}

		if application == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
			return
		}
		var organization *object.Organization
		organization, err = object.GetOrganization(util.GetId("admin", application.Organization))
		if err != nil {
			c.ResponseError(c.T(err.Error()))
			return
		}
		if organization == nil {
			c.ResponseError("organization does not exist")
			return
		}

		var provider *object.Provider
		provider, err = object.GetProvider(util.GetId("admin", authForm.Provider))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if provider == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The provider: %s does not exist"), authForm.Provider))
			return
		}

		providerItem := application.GetProviderItem(provider.Name)
		if !providerItem.IsProviderVisible() {
			c.ResponseError(fmt.Sprintf(c.T("auth:The provider: %s is not enabled for the application"), provider.Name))
			return
		}
		userInfo := &idp.UserInfo{}
		var token *oauth2.Token
		if provider.Category == "SAML" {
			// SAML
			userInfo, err = object.ParseSamlResponse(authForm.SamlResponse, provider, c.Ctx.Request.Host)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		} else if provider.Category == "OAuth" || provider.Category == "Web3" {
			// OAuth
			if err = c.consumeProviderState(authForm.State, application.GetId(), provider.Name, authForm.Method); err != nil {
				c.ResponseError(err.Error())
				return
			}
			idpInfo, err := object.FromProviderToIdpInfo(c.Ctx, provider)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			idpInfo.CodeVerifier = authForm.CodeVerifier
			var idProvider idp.IdProvider
			idProvider, err = idp.GetIdProvider(idpInfo, authForm.RedirectUri)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
			if idProvider == nil {
				c.ResponseError(fmt.Sprintf(c.T("storage:The provider type: %s is not supported"), provider.Type))
				return
			}

			setHttpClient(idProvider, provider)

			// https://github.com/golang/oauth2/issues/123#issuecomment-103715338
			token, err = idProvider.GetToken(authForm.Code)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if !token.Valid() {
				c.ResponseError(c.T("auth:Invalid token"))
				return
			}

			userInfo, err = idProvider.GetUserInfo(token)
			if err != nil {
				c.ResponseError(fmt.Sprintf(c.T("auth:Failed to login in: %s"), err.Error()))
				return
			}

			if provider.EmailRegex != "" {
				reg, err := regexp.Compile(provider.EmailRegex)
				if err != nil {
					c.ResponseError(fmt.Sprintf(c.T("auth:Failed to login in: %s"), err.Error()))
					return
				}
				if !reg.MatchString(userInfo.Email) {
					c.ResponseError(c.T("check:Email is invalid"))
				}
			}
		}

		if authForm.Method == "signup" || authForm.Method == "signin" {
			user := &object.User{}
			if provider.Category == "SAML" && !object.IsFlexibleCustomProvider(provider.Type) {
				// The userInfo.Id is the NameID in SAML response, it could be name / email / phone
				user, err = object.GetUserByFields(application.Organization, userInfo.Id)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}
			} else if provider.Category == "OAuth" || provider.Category == "Web3" || object.IsFlexibleCustomProvider(provider.Type) {
				user, err = getUserByProvider(application.Organization, provider, userInfo.Id)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}
			}

			if user != nil && !user.IsDeleted {
				// Sign in via OAuth (want to sign up but already have account)
				// sync info from 3rd-party if possible
				_, err = object.SetUserOAuthProperties(organization, user, provider.Type, userInfo, token, provider.UserMapping)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}

				authenticationContext, contextErr := c.beginAuthentication(user, []string{"federated"}, provider.Name, authForm.Type, application, authForm.UserCode)
				if contextErr != nil {
					c.ResponseError(contextErr.Error())
					return
				}
				if checkMfaEnable(c, user, organization, verificationType) {
					return
				}
				if contextErr = c.completeAuthentication(authenticationContext); contextErr != nil {
					c.ResponseError(contextErr.Error())
					return
				}

				resp = c.HandleLoggedIn(application, user, &authForm)

				c.Ctx.Input.SetParam("recordUserId", user.GetId())
			} else if provider.Category == "OAuth" || provider.Category == "Web3" || provider.Category == "SAML" {
				// Sign up via OAuth
				user, err = getExistUserByBindingRule(providerItem, application, userInfo)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}

				if user == nil {
					if !application.EnableSignUp {
						c.ResponseError(fmt.Sprintf(c.T("auth:The account for provider: %s and username: %s (%s) does not exist and is not allowed to sign up as new account, please contact your IT support"), provider.Type, userInfo.Username, userInfo.DisplayName))
						return
					}

					if !providerItem.CanSignUp {
						c.ResponseError(fmt.Sprintf(c.T("auth:The account for provider: %s and username: %s (%s) does not exist and is not allowed to sign up as new account via %s, please use another way to sign up"), provider.Type, userInfo.Username, userInfo.DisplayName, provider.Type))
						return
					}

					// Check and validate invitation code
					invitation, msg := object.CheckInvitationCode(application, organization, &authForm, c.GetAcceptLanguage())
					if msg != "" {
						c.ResponseError(msg)
						return
					}
					invitationName := ""
					if invitation != nil {
						invitationName = invitation.Name
					}

					// Handle UseEmailAsUsername for OAuth and Web3
					if organization.UseEmailAsUsername && userInfo.Email != "" {
						userInfo.Username = userInfo.Email
					}

					// Handle username conflicts
					var tmpUser *object.User
					tmpUser, err = object.GetUser(util.GetId(application.Organization, userInfo.Username))
					if err != nil {
						c.ResponseError(err.Error())
						return
					}

					if tmpUser != nil {
						uidStr := strings.Split(util.GenerateUUID(), "-")
						userInfo.Username = fmt.Sprintf("%s_%s", userInfo.Username, uidStr[1])
					}

					properties := map[string]string{}
					var count int64
					count, err = object.GetUserCount(application.Organization, "", "", "")
					if err != nil {
						c.ResponseError(err.Error())
						return
					}

					properties["no"] = strconv.Itoa(int(count + 2))
					var initScore int
					initScore, err = organization.GetInitScore()
					if err != nil {
						c.ResponseError(fmt.Errorf(c.T("account:Get init score failed, error: %w"), err).Error())
						return
					}

					userId := userInfo.Id
					if userId == "" {
						userId = util.GenerateId()
					}

					user = &object.User{
						Owner:             application.Organization,
						Name:              userInfo.Username,
						CreatedTime:       util.GetCurrentTime(),
						Id:                userId,
						Type:              "normal-user",
						DisplayName:       userInfo.DisplayName,
						Avatar:            userInfo.AvatarUrl,
						Address:           []string{},
						Email:             userInfo.Email,
						Phone:             userInfo.Phone,
						CountryCode:       userInfo.CountryCode,
						Region:            userInfo.CountryCode,
						Score:             initScore,
						IsAdmin:           false,
						IsForbidden:       false,
						IsDeleted:         false,
						SignupApplication: application.Name,
						Properties:        properties,
						Invitation:        invitationName,
						InvitationCode:    authForm.InvitationCode,
						RegisterType:      "Application Signup",
						RegisterSource:    fmt.Sprintf("%s/%s", application.Organization, application.Name),
					}

					// Set group from invitation code if available, otherwise use provider's signup group or application's default group
					if invitation != nil && invitation.SignupGroup != "" {
						user.Groups = []string{invitation.SignupGroup}
					} else if providerItem.SignupGroup != "" {
						user.Groups = []string{providerItem.SignupGroup}
					} else if application.DefaultGroup != "" {
						user.Groups = []string{application.DefaultGroup}
					}

					if application.DefaultTag != "" && user.Tag == "" {
						user.Tag = application.DefaultTag
					}

					var affected bool
					affected, err = object.AddUser(user, c.GetAcceptLanguage())
					if err != nil {
						c.ResponseError(err.Error())
						return
					}

					if !affected {
						c.ResponseError(fmt.Sprintf(c.T("auth:Failed to create user, user information is invalid: %s"), util.StructToJson(user)))
						return
					}

					// Increment invitation usage count
					if invitation != nil {
						invitation.UsedCount += 1
						_, err = object.UpdateInvitation(invitation.GetId(), invitation, c.GetAcceptLanguage())
						if err != nil {
							c.ResponseError(err.Error())
							return
						}
					}
				}

				// sync info from 3rd-party if possible
				_, err = object.SetUserOAuthProperties(organization, user, provider.Type, userInfo, token, provider.UserMapping)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}

				_, err = linkUserByProvider(user, provider, userInfo.Id)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}

				authenticationContext, contextErr := c.beginAuthentication(user, []string{"federated"}, provider.Name, authForm.Type, application, authForm.UserCode)
				if contextErr != nil {
					c.ResponseError(contextErr.Error())
					return
				}
				if checkMfaEnable(c, user, organization, verificationType) {
					return
				}
				if contextErr = c.completeAuthentication(authenticationContext); contextErr != nil {
					c.ResponseError(contextErr.Error())
					return
				}
				resp = c.HandleLoggedIn(application, user, &authForm)

				c.Ctx.Input.SetParam("recordUserId", user.GetId())
				c.Ctx.Input.SetParam("recordSignup", "true")
			} else if provider.Category == "SAML" {
				// TODO: since we get the user info from SAML response, we can try to create the user
				resp = &Response{Status: "error", Msg: fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(application.Organization, userInfo.Id))}
			}
			// resp = &Response{Status: "ok", Msg: "", Data: res}
		} else { // authForm.Method == "link"
			userId := c.GetSessionUsername()
			if userId == "" {
				c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), util.GetId(application.Organization, userInfo.Id)), userInfo)
				return
			}

			var oldUser *object.User
			oldUser, err = getUserByProvider(application.Organization, provider, userInfo.Id)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if oldUser != nil {
				c.ResponseError(fmt.Sprintf(c.T("auth:The account for provider: %s and username: %s (%s) is already linked to another account: %s (%s)"), provider.Type, userInfo.Username, userInfo.DisplayName, oldUser.Name, oldUser.DisplayName))
				return
			}

			var user *object.User
			user, err = object.GetUser(userId)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			// sync info from 3rd-party if possible
			_, err = object.SetUserOAuthProperties(organization, user, provider.Type, userInfo, token, provider.UserMapping)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			var isLinked bool
			isLinked, err = linkUserByProvider(user, provider, userInfo.Id)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if isLinked {
				resp = &Response{Status: "ok", Msg: "", Data: isLinked}
			} else {
				resp = &Response{Status: "error", Msg: "Failed to link user account", Data: isLinked}
			}
		}
	} else if mfaUserId := c.getMfaUserSession(); mfaUserId != "" {
		var user *object.User
		user, err = object.GetUser(mfaUserId)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if user == nil {
			c.ResponseError(mfaRestartLoginMessage)
			return
		}
		pendingAuthentication, err := c.getPendingAuthentication()
		if err != nil {
			c.ResponseError(mfaRestartLoginMessage)
			return
		}
		if pendingAuthentication.Context.Subject != user.GetId() {
			c.ResponseError(mfaRestartLoginMessage)
			return
		}
		if authForm.Type != pendingAuthentication.FlowType {
			c.ResponseError("authentication flow type does not match pending MFA authentication")
			return
		}
		if authForm.UserCode != pendingAuthentication.UserCode {
			c.ResponseError("device user code does not match pending MFA authentication")
			return
		}
		if pendingAuthentication.Request != nil {
			currentRequest, requestErr := c.captureAuthorizationRequest()
			if requestErr != nil {
				c.ResponseError(requestErr.Error())
				return
			}
			if !currentRequest.Equal(*pendingAuthentication.Request) {
				c.ResponseError("OAuth authorization request does not match pending MFA authentication")
				return
			}
		}

		var application *object.Application
		if authForm.ClientId == "" {
			application, err = object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
		} else {
			application, err = object.GetApplicationByClientId(authForm.ClientId)
		}
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if application == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
			return
		}
		if application.GetId() != pendingAuthentication.ApplicationId {
			c.ResponseError("application does not match pending MFA authentication")
			return
		}
		if pendingAuthentication.Request != nil &&
			application.ClientId != pendingAuthentication.Request.ClientId {
			c.ResponseError("OAuth client does not match pending authentication")
			return
		}

		var organization *object.Organization
		organization, err = object.GetOrganization(util.GetId("admin", application.Organization))
		if err != nil {
			c.ResponseError(c.T(err.Error()))
			return
		}
		if organization == nil {
			c.ResponseError("organization does not exist")
			return
		}

		additionalAuthenticationMethod := ""
		if authForm.Passcode != "" {
			if authForm.MfaType == c.GetSession("verificationCodeType") {
				c.ResponseError("Invalid multi-factor authentication type")
				return
			}
			user.CountryCode = user.GetCountryCode(user.CountryCode)
			mfaUtil := object.GetMfaUtil(authForm.MfaType, user.GetMfaProps(authForm.MfaType, false))
			if mfaUtil == nil {
				c.ResponseError("Invalid multi-factor authentication type")
				return
			}

			passed, err := c.checkOrgMasterVerificationCode(user, authForm.Passcode)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if !passed {
				err = mfaUtil.Verify(authForm.Passcode)
				if err != nil {
					c.Ctx.Input.SetParam("recordDetail", object.SigninReasonMfaFailed)
					c.ResponseError(err.Error())
					return
				}
				additionalAuthenticationMethod, err = mfaAuthenticationMethod(authForm.MfaType)
				if err != nil {
					c.ResponseError(err.Error())
					return
				}
			} else {
				additionalAuthenticationMethod = "master_verification_code"
			}

			// The legacy MfaRememberDeadline is a global user field and therefore
			// suppresses MFA on every browser and client. It is intentionally not
			// written or trusted by the hardened authentication flow.
			c.SetSession("verificationCodeType", "")
		} else if authForm.RecoveryCode != "" {
			err = object.MfaRecover(user, authForm.RecoveryCode)
			if err != nil {
				c.Ctx.Input.SetParam("recordDetail", object.SigninReasonMfaFailed)
				c.ResponseError(err.Error())
				return
			}
			additionalAuthenticationMethod = "recovery"
		} else {
			c.ResponseError("missing passcode or recovery code")
			return
		}

		authenticationContext, err := appendAuthenticationMethod(pendingAuthentication.Context, additionalAuthenticationMethod)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if err = c.completeAuthentication(authenticationContext); err != nil {
			c.ResponseError(err.Error())
			return
		}
		pendingAuthentication.Context = authenticationContext
		if err = c.setPendingAuthentication(pendingAuthentication); err != nil {
			c.ResponseError(err.Error())
			return
		}

		resp = c.HandleLoggedIn(application, user, &authForm)
		c.setMfaUserSession("")

		c.Ctx.Input.SetParam("recordUserId", user.GetId())
	} else {
		if c.GetSessionUsername() != "" {
			// user already signed in to Casdoor, so let the user click the avatar button to do the quick sign-in
			var application *object.Application
			application, err = object.GetApplication(fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			if application == nil {
				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}

			if authForm.Provider == "" {
				authForm.Provider = authForm.ProviderBack
			}

			user := c.getCurrentUser()
			authenticationContext, contextErr := c.getCurrentAuthenticationContext()
			if contextErr != nil {
				c.ResponseError("fresh authentication is required")
				return
			}
			if user == nil || authenticationContext.Subject != user.GetId() {
				c.ResponseError("authentication context does not match signed-in user")
				return
			}
			if authForm.Type == ResponseTypeCode {
				authorizationRequest, requestErr := c.captureAuthorizationRequest()
				if requestErr != nil {
					c.ResponseError(requestErr.Error())
					return
				}
				if authorizationRequest.RequiresFreshAuthentication(authenticationContext, time.Now().Unix()) {
					c.ResponseError("fresh authentication is required")
					return
				}
				pendingAuthentication := newPendingAuthentication(
					authenticationContext,
					ResponseTypeCode,
					application,
					"",
					&authorizationRequest,
				)
				if contextErr = c.setPendingAuthentication(pendingAuthentication); contextErr != nil {
					c.ResponseError(contextErr.Error())
					return
				}
			}
			resp = c.HandleLoggedIn(application, user, &authForm)

			c.Ctx.Input.SetParam("recordUserId", user.GetId())
		} else {
			if isMfaContinuationSubmission(&authForm) {
				c.ResponseError(mfaRestartLoginMessage)
				return
			}
			c.ResponseError(unknownAuthenticationTypeMessage(c.GetAcceptLanguage(), &authForm))
			return
		}
	}

	if authForm.Language != "" {
		user := c.getCurrentUser()
		if user != nil {
			user.Language = authForm.Language
			_, err = object.UpdateUser(user.GetId(), user, []string{"language"}, user.IsAdmin)
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		}
	}

	c.Data["json"] = resp
	c.ServeJSON()
}

func isMfaContinuationSubmission(authForm *form.AuthForm) bool {
	if authForm == nil {
		return false
	}
	return strings.TrimSpace(authForm.Passcode) != "" || strings.TrimSpace(authForm.RecoveryCode) != ""
}

func unknownAuthenticationTypeMessage(lang string, authForm *form.AuthForm) string {
	safeForm := struct {
		Type         string `json:"type"`
		SigninMethod string `json:"signinMethod"`
		Organization string `json:"organization"`
		Application  string `json:"application"`
	}{
		Type:         authForm.Type,
		SigninMethod: authForm.SigninMethod,
		Organization: authForm.Organization,
		Application:  authForm.Application,
	}
	return fmt.Sprintf(
		i18n.Translate(lang, "auth:Unknown authentication type (not password or provider), form = %s"),
		util.StructToJson(safeForm),
	)
}

func (c *ApiController) GetSamlLogin() {
	providerId := c.Ctx.Input.Query("id")
	relayState := c.Ctx.Input.Query("relayState")
	authURL, method, err := object.GenerateSamlRequest(providerId, relayState, c.Ctx.Request.Host, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(authURL, method)
}

func (c *ApiController) HandleSamlLogin() {
	relayState := c.Ctx.Input.Query("RelayState")
	samlResponse := c.Ctx.Input.Query("SAMLResponse")
	decode, err := base64.StdEncoding.DecodeString(relayState)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	slice := strings.Split(string(decode), "&")
	if len(slice) < 5 {
		c.ResponseError("invalid RelayState format")
		return
	}
	redirectTarget := slice[4]
	if !object.IsValidSamlRedirectURL(redirectTarget, c.Ctx.Request.Host) {
		c.ResponseError("invalid redirect URL in RelayState: must point to this Casdoor instance")
		return
	}
	relayState = url.QueryEscape(relayState)
	samlResponse = url.QueryEscape(samlResponse)
	targetUrl := fmt.Sprintf("%s?relayState=%s&samlResponse=%s",
		redirectTarget, relayState, samlResponse)
	c.Redirect(targetUrl, http.StatusSeeOther)
}

// HandleOfficialAccountEvent ...
// @Tag System API
// @Title HandleOfficialAccountEvent
// @Description Handle WeChat Official Account webhook event
// @Param   signature query string false "WeChat signature"
// @Param   timestamp query string false "WeChat timestamp"
// @Param   nonce     query string false "WeChat nonce"
// @router /webhook [POST]
// @Success 200 {object} controllers.Response The Response object
func (c *ApiController) HandleOfficialAccountEvent() {
	if c.Ctx.Request.Method == "GET" {
		s := c.Ctx.Request.FormValue("echostr")
		echostr, _ := strconv.Atoi(s)
		c.SetData(echostr)
		c.ServeJSON()
		return
	}
	respBytes, err := io.ReadAll(c.Ctx.Request.Body)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	signature := c.Ctx.Input.Query("signature")
	timestamp := c.Ctx.Input.Query("timestamp")
	nonce := c.Ctx.Input.Query("nonce")
	var data struct {
		MsgType      string `xml:"MsgType"`
		Event        string `xml:"Event"`
		EventKey     string `xml:"EventKey"`
		FromUserName string `xml:"FromUserName"`
		Ticket       string `xml:"Ticket"`
	}
	err = xml.Unmarshal(respBytes, &data)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if strings.ToUpper(data.Event) != "SCAN" && strings.ToUpper(data.Event) != "SUBSCRIBE" {
		c.Ctx.WriteString("")
		return
	}
	if data.Ticket == "" {
		c.ResponseError("empty ticket")
		return
	}

	providerId := data.EventKey
	provider, err := object.GetProvider(providerId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if provider == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The provider: %s does not exist"), providerId))
		return
	}

	if !idp.VerifyWechatSignature(provider.Content, nonce, timestamp, signature) {
		c.ResponseError("invalid signature")
		return
	}

	idp.Lock.Lock()
	if idp.WechatCacheMap == nil {
		idp.WechatCacheMap = make(map[string]idp.WechatCacheMapValue)
	}
	idp.WechatCacheMap[data.Ticket] = idp.WechatCacheMapValue{
		IsScanned:     true,
		WechatUnionId: data.FromUserName,
	}
	idp.Lock.Unlock()

	c.Ctx.WriteString("")
}

// GetWebhookEventType ...
// @Tag System API
// @Title GetWebhookEventType
// @router /get-webhook-event [GET]
// @Param   ticket     query    string  true        "The eventId of QRCode"
// @Success 200 {object} controllers.Response The Response object
func (c *ApiController) GetWebhookEventType() {
	ticket := c.Ctx.Input.Query("ticket")

	idp.Lock.RLock()
	_, ok := idp.WechatCacheMap[ticket]
	idp.Lock.RUnlock()
	if !ok {
		c.ResponseError("ticket not found")
		return
	}

	c.ResponseOk("SCAN", ticket)
}

// GetQRCode
// @Tag System API
// @Title GetWechatQRCode
// @router /get-qrcode [GET]
// @Param   id     query    string  true        "The id ( owner/name ) of provider"
// @Success 200 {object} controllers.Response The Response object
func (c *ApiController) GetQRCode() {
	providerId := c.Ctx.Input.Query("id")
	provider, err := object.GetProvider(providerId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if provider == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The provider: %s does not exist"), providerId))
		return
	}

	code, ticket, err := idp.GetWechatOfficialAccountQRCode(provider.ClientId2, provider.ClientSecret2, providerId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(code, ticket)
}

// GetCaptchaStatus
// @Title GetCaptchaStatus
// @Tag Token API
// @Description Get Login Error Counts
// @Param   id     query    string  true        "The id ( owner/name ) of user"
// @Success 200 {object} controllers.Response The Response object
// @router /get-captcha-status [get]
func (c *ApiController) GetCaptchaStatus() {
	organization := c.Ctx.Input.Query("organization")
	userId := c.Ctx.Input.Query("userId")
	applicationName := c.Ctx.Input.Query("application")

	application, err := object.GetApplication(fmt.Sprintf("admin/%s", applicationName))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError("application not found")
		return
	}

	clientIp := util.GetClientIpFromRequest(c.Ctx.Request)
	captchaEnabled, err := object.CheckToEnableCaptcha(application, organization, userId, clientIp)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(captchaEnabled)
	return
}

// Callback
// @Title Callback
// @Tag Callback API
// @Description Handle OAuth callback redirect
// @Param   code  query string false "OAuth authorization code"
// @Param   state query string false "OAuth state parameter"
// @router /Callback [post]
// @Success 200 {object} object.Userinfo The Response object
func (c *ApiController) Callback() {
	code := c.GetString("code")
	state := c.GetString("state")

	frontendCallbackUrl := fmt.Sprintf("/callback?code=%s&state=%s", url.QueryEscape(code), url.QueryEscape(state))
	c.Ctx.Redirect(http.StatusFound, frontendCallbackUrl)
}

// DeviceAuth
// @Title DeviceAuth
// @Tag Device Authorization Endpoint
// @Description Endpoint for the device authorization flow
// @Param   client_id query string true  "The OAuth2 client ID"
// @Param   scope     query string false "The requested scope"
// @router /device-auth [post]
// @Success 200 {object} object.DeviceAuthResponse The Response object
func (c *ApiController) DeviceAuth() {
	clientId := c.Ctx.Input.Query("client_id")
	scope := c.Ctx.Input.Query("scope")
	application, err := object.GetApplicationByClientId(clientId)
	if err != nil {
		c.Data["json"] = object.TokenError{
			Error:            err.Error(),
			ErrorDescription: err.Error(),
		}
		c.ServeJSON()
		return
	}

	if application == nil {
		c.Data["json"] = object.TokenError{
			Error:            c.T("token:Invalid client_id"),
			ErrorDescription: c.T("token:Invalid client_id"),
		}
		c.ServeJSON()
		return
	}

	if !application.HasSigninMethod("Device login") {
		c.Data["json"] = object.TokenError{
			Error:            object.UnauthorizedClient,
			ErrorDescription: "device login is not enabled for this application",
		}
		c.ServeJSON()
		return
	}
	expandedScope, deviceAuthError := object.ValidateDeviceAuthorizationRequest(application, scope)
	if deviceAuthError != nil {
		c.Data["json"] = deviceAuthError
		c.ServeJSON()
		return
	}
	scope = expandedScope

	deviceCode := util.GenerateId()
	userCode := util.GetRandomName()

	generateTime := 0
	for {
		if generateTime > 5 {
			c.Data["json"] = object.TokenError{
				Error:            "userCode gen",
				ErrorDescription: c.T("token:Invalid client_id"),
			}
			c.ServeJSON()
			return
		}
		_, ok := object.DeviceAuthMap.Load(userCode)
		if !ok {
			break
		}

		generateTime++
	}

	cancelToken := util.GenerateId()

	expiresIn := application.CodeResendTimeout
	if expiresIn == 0 {
		expiresIn = object.DeviceAuthExpiresIn
	}

	deviceAuthCache := object.DeviceAuthCache{
		UserSignIn:    false,
		UserName:      "",
		Scope:         scope,
		ApplicationId: application.GetId(),
		ClientId:      application.ClientId,
		RequestAt:     time.Now(),
		Status:        object.DeviceAuthStatusPending,
		ExpiresIn:     expiresIn,
	}

	userAuthCache := object.DeviceAuthCache{
		UserSignIn:    false,
		UserName:      deviceCode,
		Scope:         scope,
		ApplicationId: application.GetId(),
		ClientId:      application.ClientId,
		RequestAt:     time.Now(),
		Status:        object.DeviceAuthStatusPending,
		CancelToken:   cancelToken,
		ExpiresIn:     expiresIn,
	}

	object.DeviceAuthMap.Store(deviceCode, deviceAuthCache)
	object.DeviceAuthMap.Store(userCode, userAuthCache)

	c.Data["json"] = object.GetDeviceAuthResponse(deviceCode, userCode, cancelToken, c.Ctx.Request.Host, expiresIn)
	c.ServeJSON()
}

// CancelDeviceAuth
// @Title CancelDeviceAuth
// @Tag Device Authorization Endpoint
// @Description cancel a pending device authorization flow
// @Param   userCode    query string true "The user code to cancel"
// @Param   cancelToken query string true "The cancellation token"
// @router /cancel-device-auth [post]
func (c *ApiController) CancelDeviceAuth() {
	userCode := c.Ctx.Input.Query("userCode")
	cancelToken := c.Ctx.Input.Query("cancelToken")

	deviceAuthCache, ok := object.DeviceAuthMap.Load(userCode)
	if !ok {
		c.ResponseError(c.T("auth:UserCode Invalid"))
		return
	}

	userCodeCache := deviceAuthCache.(object.DeviceAuthCache)
	if userCodeCache.CancelToken == "" || userCodeCache.CancelToken != cancelToken {
		c.ResponseError(c.T("auth:UserCode Invalid"))
		return
	}

	object.DeviceAuthMap.Delete(userCode)

	if userCodeCache.UserName != "" {
		object.DeviceAuthMap.Delete(userCodeCache.UserName)
	}

	c.ResponseOk("Canceled")
}

// DeviceAuthComplete
// @Title DeviceAuthComplete
// @Tag Device Authorization Endpoint
// @Description Complete device authorization by establishing a browser session after token issuance
// @Param   deviceCode query string true "The device code to complete"
// @router /device-auth-complete [post]
func (c *ApiController) DeviceAuthComplete() {
	deviceCode := c.Ctx.Input.Query("deviceCode")
	if deviceCode == "" {
		c.ResponseError(c.T("auth:DeviceCode Invalid"))
		return
	}

	deviceAuthCacheAny, ok := object.DeviceAuthMap.Load(deviceCode)
	if !ok {
		c.ResponseError(c.T("auth:DeviceCode Invalid"))
		return
	}

	deviceAuthCache := deviceAuthCacheAny.(object.DeviceAuthCache)
	if deviceAuthCache.Status != object.DeviceAuthStatusTokenIssued {
		c.ResponseError(c.T("auth:DeviceCode Invalid"))
		return
	}

	if deviceAuthCache.RequestAt.Add(time.Duration(deviceAuthCache.ExpiresIn) * time.Second).Before(time.Now()) {
		object.DeviceAuthMap.Delete(deviceCode)
		c.ResponseError(c.T("auth:UserCode Expired"))
		return
	}

	application, err := object.GetApplication(deviceAuthCache.ApplicationId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), deviceAuthCache.ApplicationId))
		return
	}

	user, err := object.GetUserByFields(application.Organization, deviceAuthCache.UserName)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), deviceAuthCache.UserName))
		return
	}
	authenticationContext, contextErr := object.PreserveAuthenticationContext(deviceAuthCache.AuthenticationContext)
	if contextErr != nil || authenticationContext.Subject != user.GetId() {
		c.ResponseError(c.T("auth:Verified authentication context is missing"))
		return
	}
	if contextErr = c.completeAuthentication(authenticationContext); contextErr != nil {
		c.ResponseError(contextErr.Error())
		return
	}

	responseType := c.Ctx.Input.Query("responseType")
	if responseType == "" {
		responseType = "login"
	}
	if responseType != "login" {
		requestClientId := c.Ctx.Input.Query("clientId")
		if requestClientId != application.ClientId {
			c.ResponseError(c.T("auth:The application does not match the device authorization request"))
			return
		}

		if deviceAuthCache.Scope != "" {
			requestScope := c.Ctx.Input.Query("scope")
			if requestScope != "" {
				allowedScopes := make(map[string]bool)
				for _, s := range strings.Fields(deviceAuthCache.Scope) {
					allowedScopes[s] = true
				}
				for _, s := range strings.Fields(requestScope) {
					if !allowedScopes[s] {
						c.ResponseError(c.T("auth:Requested scope exceeds original device authorization scope"))
						return
					}
				}
			}
		}
		authorizationRequest, requestErr := c.captureAuthorizationRequest()
		if requestErr != nil {
			c.ResponseError(requestErr.Error())
			return
		}
		pendingAuthentication := newPendingAuthentication(
			authenticationContext,
			responseType,
			application,
			"",
			&authorizationRequest,
		)
		if contextErr = c.setPendingAuthentication(pendingAuthentication); contextErr != nil {
			c.ResponseError(contextErr.Error())
			return
		}
	}

	object.DeviceAuthMap.Delete(deviceCode)

	authForm := form.AuthForm{
		Type: responseType,
	}
	resp := c.HandleLoggedIn(application, user, &authForm)

	c.Ctx.Input.SetParam("recordUserId", user.GetId())
	c.Data["json"] = resp
	c.ServeJSON()
}
