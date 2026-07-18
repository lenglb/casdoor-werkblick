// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

const mfaSetupTransactionLifetime = 10 * time.Minute

func isSupportedMfaSetupType(mfaType string) bool {
	// SMS/email verification records are not yet transaction- and purpose-bound;
	// RADIUS accepts a client-selected provider; Push has no verifiable approval
	// callback. Until those protocols are completed, only TOTP enrollment is a
	// security boundary that this flow can safely promote.
	return mfaType == object.TotpType
}

type mfaSetupTransaction struct {
	Id         string          `json:"id"`
	UserId     string          `json:"userId"`
	MfaType    string          `json:"mfaType"`
	Config     object.MfaProps `json:"config"`
	Verified   bool            `json:"verified"`
	Restricted bool            `json:"restricted"`
	CreatedAt  int64           `json:"createdAt"`
	ExpiresAt  int64           `json:"expiresAt"`
}

type mfaSetupCompletion struct {
	Type         string `json:"type"`
	RedirectUrl  string `json:"redirectUrl,omitempty"`
	RedirectUri  string `json:"redirectUri,omitempty"`
	ResponseMode string `json:"responseMode,omitempty"`
	Code         string `json:"code,omitempty"`
	State        string `json:"state,omitempty"`
}

func (c *ApiController) setMfaSetupTransaction(transaction mfaSetupTransaction) error {
	if transaction.Id == "" || transaction.UserId == "" || transaction.MfaType == "" || transaction.ExpiresAt <= time.Now().Unix() {
		return fmt.Errorf("invalid MFA setup transaction")
	}
	return c.SetSession(object.MfaSetupTransaction, util.StructToJson(transaction))
}

func (c *ApiController) getMfaSetupTransaction() (mfaSetupTransaction, error) {
	value := c.GetSession(object.MfaSetupTransaction)
	serialized, ok := value.(string)
	if !ok || strings.TrimSpace(serialized) == "" {
		return mfaSetupTransaction{}, fmt.Errorf("MFA setup transaction is missing")
	}
	var transaction mfaSetupTransaction
	if err := util.JsonToStruct(serialized, &transaction); err != nil {
		return mfaSetupTransaction{}, fmt.Errorf("decode MFA setup transaction: %w", err)
	}
	if transaction.Id == "" || transaction.UserId == "" || transaction.MfaType == "" || transaction.ExpiresAt <= time.Now().Unix() {
		_ = c.DelSession(object.MfaSetupTransaction)
		return mfaSetupTransaction{}, fmt.Errorf("MFA setup transaction is invalid or expired")
	}
	return transaction, nil
}

func (c *ApiController) authorizeMfaSetupUser(user *object.User) (restricted bool, ok bool) {
	if user == nil {
		c.ResponseError("User doesn't exist")
		return false, false
	}
	if setupUserId := c.getMfaSetupUserSession(); setupUserId != "" {
		if setupUserId != user.GetId() || c.GetSessionUsername() != "" {
			c.ResponseError("MFA setup session does not match the requested user")
			return true, false
		}
		return true, true
	}
	// A normal cookie session is not sufficient to add or replace its own MFA
	// secret. Self-service enrollment needs a dedicated fresh re-authentication
	// transaction; until that exists, only the restricted post-primary flow or
	// an administrator enrolling a different account is allowed.
	if c.IsAdmin() && c.GetSessionUsername() != user.GetId() {
		return false, true
	}
	c.ResponseError("MFA self-service enrollment requires a fresh re-authentication transaction")
	return false, false
}

func ensureIndependentMfaMethod(authenticationContext object.AuthenticationContext, mfaType string) error {
	method, err := mfaAuthenticationMethod(mfaType)
	if err != nil {
		return err
	}
	if slices.Contains(authenticationContext.Amr, method) {
		return fmt.Errorf("MFA method %q is not independent from the primary authentication method", mfaType)
	}
	return nil
}

func (c *ApiController) validateRestrictedMfaSetupType(user *object.User, organization *object.Organization, mfaType string) error {
	if user == nil || organization == nil {
		return fmt.Errorf("MFA setup user or organization is missing")
	}
	if !object.IsRequiredMfaType(organization, user, mfaType) {
		return fmt.Errorf("MFA type is not required for this setup session")
	}
	pending, err := c.getPendingAuthentication()
	if err != nil {
		return err
	}
	if pending.Context.Subject != user.GetId() {
		return fmt.Errorf("pending authentication does not match the MFA setup user")
	}
	return ensureIndependentMfaMethod(pending.Context, mfaType)
}

// MfaSetupInitiate
// @Title MfaSetupInitiate
// @Tag MFA API
// @Description setup MFA
// @Param   mfaType formData string true "The type of MFA to set up (app/sms/email)"
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/initiate [post]
func (c *ApiController) MfaSetupInitiate() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	userId := util.GetId(owner, name)

	if len(userId) == 0 {
		c.ResponseError(http.StatusText(http.StatusBadRequest))
		return
	}
	if !isSupportedMfaSetupType(mfaType) {
		c.ResponseError("Only TOTP enrollment is supported by the hardened MFA setup flow")
		return
	}

	MfaUtil := object.GetMfaUtil(mfaType, nil)
	if MfaUtil == nil {
		c.ResponseError("Invalid auth type")
		return
	}

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}
	restricted, ok := c.authorizeMfaSetupUser(user)
	if !ok {
		return
	}

	organization, err := object.GetOrganizationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if organization == nil {
		c.ResponseError("Organization doesn't exist")
		return
	}
	if restricted {
		if err = c.validateRestrictedMfaSetupType(user, organization, mfaType); err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	issuer := ""
	if organization != nil && organization.DisplayName != "" {
		issuer = organization.DisplayName
	} else if organization != nil {
		issuer = organization.Name
	}

	mfaProps, err := MfaUtil.Initiate(user.GetId(), issuer)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	recoveryCode := util.GenerateUUID()
	mfaProps.RecoveryCodes = []string{recoveryCode}
	mfaProps.MfaRememberInHours = organization.MfaRememberInHours
	now := time.Now()
	transaction := mfaSetupTransaction{
		Id:         util.GenerateId(),
		UserId:     user.GetId(),
		MfaType:    mfaType,
		Config:     *mfaProps,
		Restricted: restricted,
		CreatedAt:  now.Unix(),
		ExpiresAt:  now.Add(mfaSetupTransactionLifetime).Unix(),
	}
	transaction.Config.RecoveryCodes = slices.Clone(mfaProps.RecoveryCodes)
	if err = c.setMfaSetupTransaction(transaction); err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Ctx.Input.CruSession.SessionRelease(context.Background(), c.Ctx.ResponseWriter)

	resp := mfaProps
	c.ResponseOk(resp)
}

// MfaSetupVerify
// @Title MfaSetupVerify
// @Tag MFA API
// @Description setup verify totp
// @Param   secret   formData string true "The MFA secret"
// @Param   passcode formData string true "The MFA passcode"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/verify [post]
func (c *ApiController) MfaSetupVerify() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	passcode := c.Ctx.Request.Form.Get("passcode")
	secret := c.Ctx.Request.Form.Get("secret")
	dest := c.Ctx.Request.Form.Get("dest")
	countryCode := c.Ctx.Request.Form.Get("countryCode")

	if mfaType == "" || passcode == "" {
		c.ResponseError("missing auth type or passcode")
		return
	}
	if !isSupportedMfaSetupType(mfaType) {
		c.ResponseError("Only TOTP enrollment is supported by the hardened MFA setup flow")
		return
	}
	user, err := object.GetUser(util.GetId(owner, name))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	restricted, ok := c.authorizeMfaSetupUser(user)
	if !ok {
		return
	}
	transaction, err := c.getMfaSetupTransaction()
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if transaction.UserId != user.GetId() || transaction.MfaType != mfaType || transaction.Restricted != restricted {
		c.ResponseError("MFA setup transaction does not match the request")
		return
	}
	if restricted {
		organization, organizationErr := object.GetOrganizationByUser(user)
		if organizationErr != nil {
			c.ResponseError(organizationErr.Error())
			return
		}
		if organizationErr = c.validateRestrictedMfaSetupType(user, organization, mfaType); organizationErr != nil {
			c.ResponseError(organizationErr.Error())
			return
		}
	}

	config := transaction.Config
	config.MfaType = mfaType
	if mfaType == object.TotpType {
		if secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(transaction.Config.Secret)) != 1 {
			c.ResponseError("totp secret does not match the initiated setup")
			return
		}
	} else if mfaType == object.SmsType {
		if dest == "" {
			c.ResponseError("destination is missing")
			return
		}
		config.Secret = dest
		if countryCode == "" {
			c.ResponseError("country code is missing")
			return
		}
		config.CountryCode = countryCode
	} else if mfaType == object.EmailType {
		if dest == "" {
			c.ResponseError("destination is missing")
			return
		}
		config.Secret = dest
	} else if mfaType == object.RadiusType {
		if dest == "" {
			c.ResponseError("RADIUS username is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("RADIUS provider is missing")
			return
		}
		config.URL = secret
	} else if mfaType == object.PushType {
		if dest == "" {
			c.ResponseError("push notification receiver is missing")
			return
		}
		config.Secret = dest
		if secret == "" {
			c.ResponseError("push notification provider is missing")
			return
		}
		config.URL = secret
	}

	mfaUtil := object.GetMfaUtil(mfaType, &config)
	if mfaUtil == nil {
		c.ResponseError("Invalid multi-factor authentication type")
		return
	}

	err = mfaUtil.SetupVerify(passcode)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	transaction.Config = config
	transaction.Config.RecoveryCodes = slices.Clone(config.RecoveryCodes)
	transaction.Verified = true
	if err = c.setMfaSetupTransaction(transaction); err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.Ctx.Input.CruSession.SessionRelease(context.Background(), c.Ctx.ResponseWriter)
	c.ResponseOk(http.StatusText(http.StatusOK))
}

// MfaSetupEnable
// @Title MfaSetupEnable
// @Tag MFA API
// @Description enable totp
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Param   mfaType formData string true "The MFA auth type"
// @Success 200 {object} controllers.Response The Response object
// @router /mfa/setup/enable [post]
func (c *ApiController) MfaSetupEnable() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	if !isSupportedMfaSetupType(mfaType) {
		c.ResponseError("Only TOTP enrollment is supported by the hardened MFA setup flow")
		return
	}

	user, err := object.GetUser(util.GetId(owner, name))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	restricted, ok := c.authorizeMfaSetupUser(user)
	if !ok {
		return
	}
	transaction, err := c.getMfaSetupTransaction()
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if transaction.UserId != user.GetId() || transaction.MfaType != mfaType || transaction.Restricted != restricted {
		c.ResponseError("MFA setup transaction does not match the request")
		return
	}
	if restricted {
		organization, organizationErr := object.GetOrganizationByUser(user)
		if organizationErr != nil {
			c.ResponseError(organizationErr.Error())
			return
		}
		if organizationErr = c.validateRestrictedMfaSetupType(user, organization, mfaType); organizationErr != nil {
			c.ResponseError(organizationErr.Error())
			return
		}
	}
	adminEnrollment := !restricted && c.GetSessionUsername() != user.GetId() && c.IsAdmin()
	if !transaction.Verified && !adminEnrollment {
		c.ResponseError("MFA setup must be verified before it can be enabled")
		return
	}
	if !claimPendingAuthenticationTransaction(transaction.Id, transaction.ExpiresAt, time.Now().Unix()) {
		c.ResponseError("MFA setup transaction has already been consumed")
		return
	}
	releaseClaim := true
	defer func() {
		if releaseClaim {
			consumedAuthenticationTransactions.Delete(transaction.Id)
		}
	}()

	config := transaction.Config
	config.RecoveryCodes = slices.Clone(transaction.Config.RecoveryCodes)
	if len(config.RecoveryCodes) == 0 {
		c.ResponseError("MFA setup recovery code is missing")
		return
	}
	if mfaType == object.EmailType && user.Email == "" {
		user.Email = config.Secret
	}
	if mfaType == object.SmsType && user.Phone == "" {
		user.Phone = config.Secret
		user.CountryCode = config.CountryCode
	}
	mfaUtil := object.GetMfaUtil(mfaType, &config)
	if mfaUtil == nil {
		c.ResponseError("Invalid multi-factor authentication type")
		return
	}

	err = mfaUtil.Enable(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	releaseClaim = false
	if err = c.DelSession(object.MfaSetupTransaction); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if restricted {
		c.completeRequiredMfaSetup(user, mfaType)
		return
	}
	c.ResponseOk(http.StatusText(http.StatusOK))
}

func (c *ApiController) completeRequiredMfaSetup(user *object.User, mfaType string) {
	pending, err := c.getPendingAuthentication()
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if pending.Context.Subject != user.GetId() {
		c.ResponseError("pending authentication does not match the MFA setup user")
		return
	}
	if pending.FlowType != ResponseTypeLogin && pending.FlowType != ResponseTypeCode {
		c.ClearUserSession()
		c.ClearTokenSession()
		c.ResponseError("Required MFA completion supports login and authorization-code flows only; please authenticate again")
		return
	}
	if err = ensureIndependentMfaMethod(pending.Context, mfaType); err != nil {
		c.ResponseError(err.Error())
		return
	}
	method, err := mfaAuthenticationMethod(mfaType)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	pending.Context, err = appendAuthenticationMethod(pending.Context, method)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if err = c.setPendingAuthentication(pending); err != nil {
		c.ResponseError(err.Error())
		return
	}

	organization, err := object.GetOrganizationByUser(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if object.IsNeedPromptMfa(organization, user) {
		c.ResponseOk(mfaSetupCompletion{Type: "mfa_setup_required"})
		return
	}

	application, err := object.GetApplication(pending.ApplicationId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if application == nil {
		c.ResponseError("pending authentication application does not exist")
		return
	}
	if !c.validateAuthenticatedApplicationAccess(application, user) {
		c.ClearUserSession()
		c.ClearTokenSession()
		return
	}
	if err = c.completeAuthentication(pending.Context); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if err = c.clearMfaSetupSession(); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if err = c.setMfaUserSession(""); err != nil {
		c.ResponseError(err.Error())
		return
	}

	switch pending.FlowType {
	case ResponseTypeCode:
		c.completeRequiredMfaOAuthCode(user, application, pending)
	case ResponseTypeLogin:
		if err = c.SetSession("username", user.GetId()); err != nil {
			c.ResponseError(err.Error())
			return
		}
		if err = c.clearPendingAuthentication(); err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.setExpireForSession(application.CookieExpireInHours)
		c.ResponseOk(mfaSetupCompletion{Type: "complete"})
	}
}

func (c *ApiController) completeRequiredMfaOAuthCode(user *object.User, application *object.Application, pending object.PendingAuthentication) {
	if pending.Request == nil {
		c.ResponseError("pending OAuth authorization request is missing")
		return
	}
	request := pending.Request.Clone()
	if request.ClientId != application.ClientId || request.ExceedsMaxAge(pending.Context, time.Now().Unix()) {
		c.ResponseError("pending OAuth authorization request is no longer valid")
		return
	}
	consentRequired, err := object.CheckConsentRequired(user, application, request.Scope)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	prompts, err := request.PromptValues()
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if slices.Contains(prompts, "consent") {
		consentRequired = true
	}
	if consentRequired {
		if err = c.SetSession("username", user.GetId()); err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.setExpireForSession(application.CookieExpireInHours)
		c.ResponseOk(mfaSetupCompletion{Type: "consent", RedirectUrl: buildMfaConsentUrl(application, request)})
		return
	}

	if err = c.consumePendingAuthentication(pending.TransactionId, pending.ExpiresAt); err != nil {
		c.ResponseError(mfaRestartLoginMessage)
		return
	}
	code, err := object.GetOAuthCodeWithAuthenticationContext(
		user.GetId(), request.ClientId, pending.Context, request.ResponseType,
		request.RedirectUri, request.Scope, request.State, request.Nonce,
		request.CodeChallenge, request.Resource, c.Ctx.Request.Host, c.GetAcceptLanguage(),
	)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if code == nil || code.Message != "" || code.Code == "" {
		message := "OAuth authorization code could not be issued"
		if code != nil && code.Message != "" {
			message = code.Message
		}
		c.ResponseError(message)
		return
	}
	if application.EnableSigninSession || application.HasPromptPage() {
		if err = c.SetSession("username", user.GetId()); err != nil {
			c.ResponseError(err.Error())
			return
		}
	}
	if request.ResponseMode == "form_post" {
		c.ResponseOk(mfaSetupCompletion{
			Type:         "oauth_code",
			RedirectUri:  request.RedirectUri,
			ResponseMode: request.ResponseMode,
			Code:         code.Code,
			State:        request.State,
		})
		return
	}
	redirectUrl, err := buildOAuthCallbackUrl(request.RedirectUri, code.Code, request.State)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(mfaSetupCompletion{Type: "oauth_code", RedirectUrl: redirectUrl})
}

func buildMfaConsentUrl(application *object.Application, request object.AuthorizationRequest) string {
	values := url.Values{}
	values.Set("client_id", request.ClientId)
	values.Set("response_type", request.ResponseType)
	if request.ResponseMode != "" {
		values.Set("response_mode", request.ResponseMode)
	}
	values.Set("redirect_uri", request.RedirectUri)
	values.Set("scope", request.Scope)
	values.Set("state", request.State)
	values.Set("nonce", request.Nonce)
	if request.CodeChallenge != "" {
		values.Set("code_challenge", request.CodeChallenge)
		values.Set("code_challenge_method", request.ChallengeMethod)
	}
	if request.Resource != "" {
		values.Set("resource", request.Resource)
	}
	if request.Prompt != "" {
		values.Set("prompt", request.Prompt)
	}
	if request.MaxAge != nil {
		values.Set("max_age", strconv.FormatInt(*request.MaxAge, 10))
	}
	return "/consent/" + url.PathEscape(application.Name) + "?" + values.Encode()
}

func buildOAuthCallbackUrl(redirectUri string, code string, state string) (string, error) {
	redirectUrl, err := url.Parse(redirectUri)
	if err != nil {
		return "", err
	}
	query := redirectUrl.Query()
	query.Set("code", code)
	query.Set("state", state)
	redirectUrl.RawQuery = query.Encode()
	return redirectUrl.String(), nil
}

func (c *ApiController) approveRequiredMfaDeviceFlow(user *object.User, application *object.Application, pending object.PendingAuthentication) error {
	if pending.UserCode == "" {
		return fmt.Errorf("pending device user code is missing")
	}
	userCodeCache, ok := object.DeviceAuthMap.LoadAndDelete(pending.UserCode)
	if !ok {
		return fmt.Errorf("device user code has expired")
	}
	userCode, ok := userCodeCache.(object.DeviceAuthCache)
	if !ok || userCode.ApplicationId != application.GetId() || userCode.ClientId != application.ClientId {
		return fmt.Errorf("device authorization application does not match")
	}
	deviceCodeCache, ok := object.DeviceAuthMap.Load(userCode.UserName)
	if !ok {
		return fmt.Errorf("device code has expired")
	}
	deviceCode, ok := deviceCodeCache.(object.DeviceAuthCache)
	if !ok || deviceCode.ApplicationId != application.GetId() || deviceCode.ClientId != application.ClientId {
		return fmt.Errorf("device authorization application does not match")
	}
	deviceCode.UserName = user.Name
	deviceCode.UserSignIn = true
	deviceCode.Status = object.DeviceAuthStatusApproved
	deviceCode.AuthenticationContext = pending.Context
	object.DeviceAuthMap.Store(userCode.UserName, deviceCode)
	return nil
}

// DeleteMfa
// @Title DeleteMfa
// @Tag MFA API
// @Description Delete MFA
// @Param   owner formData string true "The owner of the user"
// @Param   name  formData string true "The name of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-mfa/ [post]
func (c *ApiController) DeleteMfa() {
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	userId := util.GetId(owner, name)

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	err = object.DisabledMultiFactorAuth(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(object.GetAllMfaProps(user, true))
}

// SetPreferredMfa
// @Title SetPreferredMfa
// @Tag MFA API
// @Description Set preferred MFA
// @Param   mfaType formData string true "The MFA type to set as preferred"
// @Param   owner   formData string true "The owner of the user"
// @Param   name    formData string true "The name of the user"
// @Success 200 {object} controllers.Response The Response object
// @router /set-preferred-mfa [post]
func (c *ApiController) SetPreferredMfa() {
	mfaType := c.Ctx.Request.Form.Get("mfaType")
	owner := c.Ctx.Request.Form.Get("owner")
	name := c.Ctx.Request.Form.Get("name")
	userId := util.GetId(owner, name)

	user, err := object.GetUser(userId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError("User doesn't exist")
		return
	}

	err = object.SetPreferredMultiFactorAuth(user, mfaType)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(object.GetAllMfaProps(user, true))
}
