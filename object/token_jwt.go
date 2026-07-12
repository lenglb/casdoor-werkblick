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

package object

import (
	"crypto/subtle"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	*User
	TokenType             string            `json:"tokenType,omitempty"`
	Nonce                 string            `json:"nonce,omitempty"`
	Tag                   string            `json:"tag"`
	Scope                 string            `json:"scope,omitempty"`
	AuthenticationMethods []string          `json:"amr,omitempty"`
	AuthTime              int64             `json:"auth_time,omitempty"`
	Acr                   string            `json:"acr,omitempty"`
	Cnf                   *DPoPConfirmation `json:"cnf,omitempty"`
	// the `azp` (Authorized Party) claim. Optional. See https://openid.net/specs/openid-connect-core-1_0.html#IDToken
	Azp      string `json:"azp,omitempty"`
	Provider string `json:"provider,omitempty"`

	SigninMethod string `json:"signinMethod,omitempty"`
	jwt.RegisteredClaims
}

type UserShort struct {
	Owner string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name  string `xorm:"varchar(100) notnull pk" json:"name"`

	Id            string `xorm:"varchar(100) index" json:"id"`
	DisplayName   string `xorm:"varchar(100)" json:"displayName"`
	Avatar        string `xorm:"varchar(500)" json:"avatar"`
	Email         string `xorm:"varchar(100) index" json:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Phone         string `xorm:"varchar(100) index" json:"phone"`
}

type UserStandard struct {
	Owner string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name  string `xorm:"varchar(100) notnull pk" json:"preferred_username,omitempty"`

	Id            string `xorm:"varchar(100) index" json:"id"`
	DisplayName   string `xorm:"varchar(100)" json:"name,omitempty"`
	Avatar        string `xorm:"varchar(500)" json:"picture,omitempty"`
	Email         string `xorm:"varchar(100) index" json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Phone         string `xorm:"varchar(100) index" json:"phone,omitempty"`
}

type UserWithoutThirdIdp struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100) index" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`
	DeletedTime string `xorm:"varchar(100)" json:"deletedTime"`

	Id                string   `xorm:"varchar(100) index" json:"id"`
	Type              string   `xorm:"varchar(100)" json:"type"`
	DisplayName       string   `xorm:"varchar(100)" json:"displayName"`
	FirstName         string   `xorm:"varchar(100)" json:"firstName"`
	LastName          string   `xorm:"varchar(100)" json:"lastName"`
	Avatar            string   `xorm:"varchar(500)" json:"avatar"`
	AvatarType        string   `xorm:"varchar(100)" json:"avatarType"`
	PermanentAvatar   string   `xorm:"varchar(500)" json:"permanentAvatar"`
	Email             string   `xorm:"varchar(100) index" json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Phone             string   `xorm:"varchar(100) index" json:"phone"`
	CountryCode       string   `xorm:"varchar(6)" json:"countryCode"`
	Region            string   `xorm:"varchar(100)" json:"region"`
	Location          string   `xorm:"varchar(100)" json:"location"`
	Address           []string `json:"address"`
	Affiliation       string   `xorm:"varchar(100)" json:"affiliation"`
	Title             string   `xorm:"varchar(100)" json:"title"`
	IdCardType        string   `xorm:"varchar(100)" json:"idCardType"`
	IdCard            string   `xorm:"varchar(100) index" json:"idCard"`
	Homepage          string   `xorm:"varchar(100)" json:"homepage"`
	Bio               string   `xorm:"varchar(100)" json:"bio"`
	Tag               string   `xorm:"varchar(100)" json:"tag"`
	Language          string   `xorm:"varchar(100)" json:"language"`
	Gender            string   `xorm:"varchar(100)" json:"gender"`
	Birthday          string   `xorm:"varchar(100)" json:"birthday"`
	Education         string   `xorm:"varchar(100)" json:"education"`
	Score             int      `json:"score"`
	Karma             int      `json:"karma"`
	Ranking           int      `json:"ranking"`
	IsDefaultAvatar   bool     `json:"isDefaultAvatar"`
	IsOnline          bool     `json:"isOnline"`
	IsAdmin           bool     `json:"isAdmin"`
	IsForbidden       bool     `json:"isForbidden"`
	IsDeleted         bool     `json:"isDeleted"`
	SignupApplication string   `xorm:"varchar(100)" json:"signupApplication"`
	RegisterType      string   `xorm:"varchar(100)" json:"registerType"`
	RegisterSource    string   `xorm:"varchar(100)" json:"registerSource"`

	GitHub   string `xorm:"github varchar(100)" json:"github"`
	Google   string `xorm:"varchar(100)" json:"google"`
	QQ       string `xorm:"qq varchar(100)" json:"qq"`
	WeChat   string `xorm:"wechat varchar(100)" json:"wechat"`
	Facebook string `xorm:"facebook varchar(100)" json:"facebook"`
	DingTalk string `xorm:"dingtalk varchar(100)" json:"dingtalk"`
	Weibo    string `xorm:"weibo varchar(100)" json:"weibo"`
	Gitee    string `xorm:"gitee varchar(100)" json:"gitee"`
	LinkedIn string `xorm:"linkedin varchar(100)" json:"linkedin"`
	Wecom    string `xorm:"wecom varchar(100)" json:"wecom"`
	Lark     string `xorm:"lark varchar(100)" json:"lark"`
	Gitlab   string `xorm:"gitlab varchar(100)" json:"gitlab"`

	CreatedIp      string `xorm:"varchar(100)" json:"createdIp"`
	LastSigninTime string `xorm:"varchar(100)" json:"lastSigninTime"`
	LastSigninIp   string `xorm:"varchar(100)" json:"lastSigninIp"`

	// WebauthnCredentials []webauthn.Credential `xorm:"webauthnCredentials blob" json:"webauthnCredentials"`
	PreferredMfaType string `xorm:"varchar(100)" json:"preferredMfaType"`
	MfaPhoneEnabled  bool   `json:"mfaPhoneEnabled"`
	MfaEmailEnabled  bool   `json:"mfaEmailEnabled"`
	// MultiFactorAuths    []*MfaProps           `xorm:"-" json:"multiFactorAuths,omitempty"`

	Ldap       string            `xorm:"ldap varchar(100)" json:"ldap"`
	Properties map[string]string `json:"properties"`

	Roles       []*Role       `json:"roles"`
	Permissions []*Permission `json:"permissions"`
	Groups      []string      `xorm:"groups varchar(1000)" json:"groups"`

	LastSigninWrongTime string `xorm:"varchar(100)" json:"lastSigninWrongTime"`
	SigninWrongTimes    int    `json:"signinWrongTimes"`
}

// RefreshClaims deliberately contains no user or application-defined claims.
// Refresh tokens are long-lived credentials and should only carry the metadata
// required to validate and rotate them.
type RefreshClaims struct {
	TokenType             string            `json:"tokenType"`
	Scope                 string            `json:"scope,omitempty"`
	Azp                   string            `json:"azp,omitempty"`
	AuthenticationMethods []string          `json:"amr,omitempty"`
	AuthTime              int64             `json:"auth_time,omitempty"`
	Acr                   string            `json:"acr,omitempty"`
	Cnf                   *DPoPConfirmation `json:"cnf,omitempty"`
	jwt.RegisteredClaims
}

type ClaimsShort struct {
	*UserShort
	TokenType             string            `json:"tokenType,omitempty"`
	Nonce                 string            `json:"nonce,omitempty"`
	Scope                 string            `json:"scope,omitempty"`
	Azp                   string            `json:"azp,omitempty"`
	Provider              string            `json:"provider,omitempty"`
	AuthenticationMethods []string          `json:"amr,omitempty"`
	AuthTime              int64             `json:"auth_time,omitempty"`
	Acr                   string            `json:"acr,omitempty"`
	Cnf                   *DPoPConfirmation `json:"cnf,omitempty"`

	SigninMethod string `json:"signinMethod,omitempty"`
	jwt.RegisteredClaims
}

type OIDCAddress struct {
	Formatted     string `json:"formatted"`
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

type ClaimsWithoutThirdIdp struct {
	*UserWithoutThirdIdp
	TokenType             string            `json:"tokenType,omitempty"`
	Nonce                 string            `json:"nonce,omitempty"`
	Tag                   string            `json:"tag"`
	Scope                 string            `json:"scope,omitempty"`
	Azp                   string            `json:"azp,omitempty"`
	Provider              string            `json:"provider,omitempty"`
	AuthenticationMethods []string          `json:"amr,omitempty"`
	AuthTime              int64             `json:"auth_time,omitempty"`
	Acr                   string            `json:"acr,omitempty"`
	Cnf                   *DPoPConfirmation `json:"cnf,omitempty"`

	SigninMethod string `json:"signinMethod,omitempty"`
	jwt.RegisteredClaims
}

func getShortUser(user *User) *UserShort {
	res := &UserShort{
		Owner: user.Owner,
		Name:  user.Name,

		Id:            user.Id,
		DisplayName:   user.DisplayName,
		Avatar:        user.Avatar,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Phone:         user.Phone,
	}
	return res
}

func getStandardUser(user *User) *UserStandard {
	res := &UserStandard{
		Owner: user.Owner,
		Name:  user.Name,

		Id:            user.Id,
		DisplayName:   user.DisplayName,
		Avatar:        user.Avatar,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Phone:         user.Phone,
	}
	return res
}

func getUserWithoutThirdIdp(user *User) *UserWithoutThirdIdp {
	res := &UserWithoutThirdIdp{
		Owner:       user.Owner,
		Name:        user.Name,
		CreatedTime: user.CreatedTime,
		UpdatedTime: user.UpdatedTime,
		DeletedTime: user.DeletedTime,

		Id:                user.Id,
		Type:              user.Type,
		DisplayName:       user.DisplayName,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		Avatar:            user.Avatar,
		AvatarType:        user.AvatarType,
		PermanentAvatar:   user.PermanentAvatar,
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		Phone:             user.Phone,
		CountryCode:       user.CountryCode,
		Region:            user.Region,
		Location:          user.Location,
		Address:           user.Address,
		Affiliation:       user.Affiliation,
		Title:             user.Title,
		IdCardType:        user.IdCardType,
		IdCard:            user.IdCard,
		Homepage:          user.Homepage,
		Bio:               user.Bio,
		Tag:               user.Tag,
		Language:          user.Language,
		Gender:            user.Gender,
		Birthday:          user.Birthday,
		Education:         user.Education,
		Score:             user.Score,
		Karma:             user.Karma,
		Ranking:           user.Ranking,
		IsDefaultAvatar:   user.IsDefaultAvatar,
		IsOnline:          user.IsOnline,
		IsAdmin:           user.IsAdmin,
		IsForbidden:       user.IsForbidden,
		IsDeleted:         user.IsDeleted,
		SignupApplication: user.SignupApplication,
		RegisterType:      user.RegisterType,
		RegisterSource:    user.RegisterSource,

		GitHub:   user.GitHub,
		Google:   user.Google,
		QQ:       user.QQ,
		WeChat:   user.WeChat,
		Facebook: user.Facebook,
		DingTalk: user.DingTalk,
		Weibo:    user.Weibo,
		Gitee:    user.Gitee,
		LinkedIn: user.LinkedIn,
		Wecom:    user.Wecom,
		Lark:     user.Lark,
		Gitlab:   user.Gitlab,

		CreatedIp:      user.CreatedIp,
		LastSigninTime: user.LastSigninTime,
		LastSigninIp:   user.LastSigninIp,

		PreferredMfaType: user.PreferredMfaType,
		MfaPhoneEnabled:  user.MfaPhoneEnabled,
		MfaEmailEnabled:  user.MfaEmailEnabled,

		Ldap:       user.Ldap,
		Properties: getTokenSafeProperties(user.Properties),

		Roles:       user.Roles,
		Permissions: user.Permissions,
		Groups:      user.Groups,

		LastSigninWrongTime: user.LastSigninWrongTime,
		SigninWrongTimes:    user.SigninWrongTimes,
	}

	return res
}

func getShortClaims(claims Claims) ClaimsShort {
	res := ClaimsShort{
		UserShort:             getShortUser(claims.User),
		TokenType:             claims.TokenType,
		Nonce:                 claims.Nonce,
		Scope:                 claims.Scope,
		RegisteredClaims:      claims.RegisteredClaims,
		Azp:                   claims.Azp,
		SigninMethod:          claims.SigninMethod,
		Provider:              claims.Provider,
		AuthenticationMethods: slices.Clone(claims.AuthenticationMethods),
		AuthTime:              claims.AuthTime,
		Acr:                   claims.Acr,
		Cnf:                   cloneDPoPConfirmation(claims.Cnf),
	}
	return res
}

func getClaimsWithoutThirdIdp(claims Claims) ClaimsWithoutThirdIdp {
	res := ClaimsWithoutThirdIdp{
		UserWithoutThirdIdp:   getUserWithoutThirdIdp(claims.User),
		TokenType:             claims.TokenType,
		Nonce:                 claims.Nonce,
		Tag:                   claims.Tag,
		Scope:                 claims.Scope,
		RegisteredClaims:      claims.RegisteredClaims,
		Azp:                   claims.Azp,
		SigninMethod:          claims.SigninMethod,
		Provider:              claims.Provider,
		AuthenticationMethods: slices.Clone(claims.AuthenticationMethods),
		AuthTime:              claims.AuthTime,
		Acr:                   claims.Acr,
		Cnf:                   cloneDPoPConfirmation(claims.Cnf),
	}
	return res
}

func getRefreshClaims(claims Claims, expiresAt time.Time) RefreshClaims {
	registeredClaims := claims.RegisteredClaims
	registeredClaims.ExpiresAt = jwt.NewNumericDate(expiresAt)

	return RefreshClaims{
		TokenType:             "refresh-token",
		Scope:                 claims.Scope,
		Azp:                   claims.Azp,
		AuthenticationMethods: slices.Clone(claims.AuthenticationMethods),
		AuthTime:              claims.AuthTime,
		Acr:                   claims.Acr,
		Cnf:                   cloneDPoPConfirmation(claims.Cnf),
		RegisteredClaims:      registeredClaims,
	}
}

func cloneDPoPConfirmation(confirmation *DPoPConfirmation) *DPoPConfirmation {
	if confirmation == nil {
		return nil
	}
	return &DPoPConfirmation{JKT: confirmation.JKT}
}

// DPoPConfirmationMatches compares the signed cnf claim with the persisted
// token binding. Both must be absent for a Bearer token or both must contain
// exactly the same JWK thumbprint for a DPoP token.
func DPoPConfirmationMatches(confirmation *DPoPConfirmation, persistedJkt string) bool {
	if confirmation == nil {
		return persistedJkt == ""
	}
	if confirmation.JKT == "" || persistedJkt == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(confirmation.JKT), []byte(persistedJkt)) == 1
}

func NumericDateUnix(date *jwt.NumericDate) int64 {
	if date == nil {
		return 0
	}
	return date.Unix()
}

var safeCustomTokenUserFields = map[string]struct{}{
	"Owner": {}, "Name": {}, "CreatedTime": {}, "UpdatedTime": {}, "DeletedTime": {},
	"Id": {}, "ExternalId": {}, "Type": {}, "DisplayName": {}, "FirstName": {}, "LastName": {},
	"Avatar": {}, "AvatarType": {}, "PermanentAvatar": {}, "Email": {}, "EmailVerified": {},
	"Phone": {}, "CountryCode": {}, "Region": {}, "Location": {}, "Address": {}, "Affiliation": {},
	"Title": {}, "IdCardType": {}, "IdCard": {}, "RealName": {}, "IsVerified": {}, "Homepage": {},
	"Bio": {}, "Tag": {}, "Language": {}, "Gender": {}, "Birthday": {}, "Education": {},
	"Score": {}, "Karma": {}, "Ranking": {}, "Balance": {}, "BalanceCredit": {}, "Currency": {},
	"BalanceCurrency": {}, "IsDefaultAvatar": {}, "IsOnline": {}, "IsAdmin": {}, "IsForbidden": {},
	"IsDeleted": {}, "SignupApplication": {}, "RegisterType": {}, "RegisterSource": {}, "CreatedIp": {},
	"LastSigninTime": {}, "LastSigninIp": {}, "Groups": {}, "Roles": {}, "Permissions": {},
	"permissionNames": {},
}

var reservedJwtClaimNames = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
	"azp": {}, "nonce": {}, "scope": {}, "tokentype": {}, "cnf": {}, "client_id": {},
	"provider": {}, "signinmethod": {}, "amr": {}, "acr": {}, "auth_time": {}, "sid": {},
}

func isReservedJwtClaimName(name string) bool {
	_, ok := reservedJwtClaimNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func isOAuthTokenProperty(name string) bool {
	name = strings.ToLower(name)
	// Casdoor stores provider credentials and provider-specific response data
	// below the oauth_ namespace. Treat the namespace as credential-bearing by
	// default instead of trying to maintain an incomplete suffix denylist.
	return strings.HasPrefix(name, "oauth_")
}

func getTokenSafeProperties(properties map[string]string) map[string]string {
	if properties == nil {
		return map[string]string{}
	}

	res := make(map[string]string, len(properties))
	for name, value := range properties {
		if isOAuthTokenProperty(name) {
			continue
		}
		res[name] = value
	}
	return res
}

// getUserFieldValue only returns fields explicitly approved for JWT-Custom.
// The allowlist is a security boundary: adding a field to User must not make it
// token-selectable by default.
func getUserFieldValue(user *User, fieldName string) (interface{}, bool) {
	if user == nil {
		return nil, false
	}

	// Handle special fields that need conversion
	switch fieldName {
	case "Roles":
		return getUserRoleNames(user), true
	case "Permissions":
		return getUserPermissionNames(user), true
	case "permissionNames":
		permissionNames := []string{}
		for _, val := range user.Permissions {
			permissionNames = append(permissionNames, val.Name)
		}
		return permissionNames, true
	}

	// Individual custom properties are supported, but Casdoor's stored third-
	// party OAuth credentials are never token-selectable.
	if strings.HasPrefix(fieldName, "Properties.") {
		parts := strings.SplitN(fieldName, ".", 2)
		if len(parts) == 2 {
			propName := parts[1]
			if propName == "" || isOAuthTokenProperty(propName) {
				return nil, false
			}
			if user.Properties != nil {
				if value, exists := user.Properties[propName]; exists {
					return value, true
				}
			}
		}
		return nil, false
	}

	if _, ok := safeCustomTokenUserFields[fieldName]; !ok {
		return nil, false
	}

	// Reflection is safe here because the field name has passed the explicit
	// allowlist above.
	userValue := reflect.ValueOf(user).Elem()
	userField := userValue.FieldByName(fieldName)
	if userField.IsValid() {
		return userField.Interface(), true
	}

	return nil, false
}

func getClaimsCustom(claims Claims, tokenField []string, tokenAttributes []*JwtItem) (jwt.MapClaims, error) {
	res := make(jwt.MapClaims)

	// Always include standard JWT registered claims
	res["iss"] = claims.RegisteredClaims.Issuer
	res["sub"] = claims.RegisteredClaims.Subject
	res["aud"] = claims.RegisteredClaims.Audience
	res["exp"] = claims.RegisteredClaims.ExpiresAt
	res["nbf"] = claims.RegisteredClaims.NotBefore
	res["iat"] = claims.RegisteredClaims.IssuedAt
	res["jti"] = claims.RegisteredClaims.ID

	// Always include tokenType (essential metadata)
	res["tokenType"] = claims.TokenType

	// Always include azp if present (authorized party)
	if claims.Azp != "" {
		res["azp"] = claims.Azp
	}

	// Always include nonce and scope as they are built-in OAuth/OIDC fields (even if empty)
	res["nonce"] = claims.Nonce
	res["scope"] = claims.Scope
	if len(claims.AuthenticationMethods) > 0 {
		res["amr"] = slices.Clone(claims.AuthenticationMethods)
	}
	if claims.AuthTime > 0 {
		res["auth_time"] = claims.AuthTime
	}
	if claims.Acr != "" {
		res["acr"] = claims.Acr
	}
	if claims.Cnf != nil {
		res["cnf"] = cloneDPoPConfirmation(claims.Cnf)
	}

	// Create a map for quick lookup of selected token fields
	selectedFields := make(map[string]bool)
	for _, field := range tokenField {
		selectedFields[field] = true
	}

	// Only include signinMethod and provider if they are explicitly selected in tokenFields
	if selectedFields["signinMethod"] {
		res["signinMethod"] = claims.SigninMethod
	}
	if selectedFields["provider"] {
		res["provider"] = claims.Provider
	}

	for _, field := range tokenField {
		if strings.HasPrefix(field, "Properties.") {
			/*
				Use selected properties fields as custom claims.
				Converts `Properties.my_field` to custom claim with name `my_field`.
			*/
			parts := strings.SplitN(field, ".", 2)
			if len(parts) != 2 || parts[0] != "Properties" { // Either too many segments, or not properly scoped to `Properties`, so skip.
				continue
			}
			fieldName := parts[1]
			if isReservedJwtClaimName(fieldName) {
				return nil, fmt.Errorf("JWT-Custom property cannot override reserved claim %q", fieldName)
			}
			if value, found := getUserFieldValue(claims.User, field); found {
				res[fieldName] = value
			}
		} else if field != "signinMethod" && field != "provider" {
			if value, found := getUserFieldValue(claims.User, field); found {
				newfield := util.SnakeToCamel(util.CamelToSnakeCase(field))
				res[newfield] = value
			}
		}
	}

	for _, item := range tokenAttributes {
		if item == nil {
			continue
		}
		if isReservedJwtClaimName(item.Name) {
			return nil, fmt.Errorf("JWT-Custom attribute cannot override reserved claim %q", item.Name)
		}

		var value interface{}

		// If Category is "Existing Field", get the actual field value from the user
		if item.Category == "Existing Field" {
			fieldValue, found := getUserFieldValue(claims.User, item.Value)
			if !found {
				continue
			}
			value = fieldValue
		} else {
			// Default behavior: use replaceAttributeValue for "Static Value" or empty category
			valueList := replaceAttributeValue(claims.User, item.Value)
			if len(valueList) == 0 {
				continue
			}

			if item.Type == "String" {
				value = valueList[0]
			} else {
				value = valueList
			}
		}

		res[item.Name] = value
	}

	return res, nil
}

func refineUser(user *User) *User {
	res := *user
	res.Password = ""
	res.PasswordSalt = ""
	res.PasswordType = ""
	res.Hash = ""
	res.PreHash = ""
	res.AccessToken = ""
	res.OriginalToken = ""
	res.OriginalRefreshToken = ""
	res.TotpSecret = ""
	res.RecoveryCodes = nil
	res.WebauthnCredentials = nil
	res.MultiFactorAuths = nil
	res.FaceIds = nil
	res.ManagedAccounts = nil
	res.MfaAccounts = nil
	res.MfaItems = nil
	res.MfaRememberDeadline = ""
	res.InvitationCode = ""
	res.Properties = getTokenSafeProperties(user.Properties)

	if res.Address == nil {
		res.Address = []string{}
	}
	if res.Properties == nil {
		res.Properties = map[string]string{}
	}
	if res.Roles == nil {
		res.Roles = []*Role{}
	}
	if res.Permissions == nil {
		res.Permissions = []*Permission{}
	}
	if res.Groups == nil {
		res.Groups = []string{}
	}

	return &res
}

func generateJwtToken(application *Application, user *User, provider string, signinMethod string, nonce string, scope string, resource string, host string) (string, string, string, error) {
	return generateJwtTokenInternal(application, user, provider, signinMethod, nil, "", nonce, scope, resource, host)
}

func generateJwtTokenWithAuthenticationContext(application *Application, user *User, authenticationContext AuthenticationContext, nonce string, scope string, resource string, host string) (string, string, string, error) {
	return generateJwtTokenWithAuthenticationContextAndDPoP(application, user, authenticationContext, "", nonce, scope, resource, host)
}

func generateJwtTokenWithAuthenticationContextAndDPoP(application *Application, user *User, authenticationContext AuthenticationContext, dpopJkt string, nonce string, scope string, resource string, host string, tokenNames ...string) (string, string, string, error) {
	preserved, err := PreserveAuthenticationContext(authenticationContext)
	if err != nil {
		return "", "", "", err
	}
	if preserved.Subject != user.GetId() {
		return "", "", "", fmt.Errorf("authentication context subject %q does not match user %q", preserved.Subject, user.GetId())
	}
	return generateJwtTokenInternal(application, user, preserved.Provider, "", &preserved, dpopJkt, nonce, scope, resource, host, tokenNames...)
}

func generateJwtTokenInternal(application *Application, user *User, provider string, signinMethod string, authenticationContext *AuthenticationContext, dpopJkt string, nonce string, scope string, resource string, host string, tokenNames ...string) (string, string, string, error) {
	nowTime := time.Now()
	expireTime := nowTime.Add(time.Duration(application.ExpireInHours * float64(time.Hour)))
	refreshExpireTime := nowTime.Add(time.Duration(application.RefreshExpireInHours * float64(time.Hour)))
	if application.RefreshExpireInHours == 0 {
		refreshExpireTime = expireTime
	}

	user = refineUser(user)
	if conf.GetConfigBool("useGroupPathInToken") {
		groupPath, err := user.GetUserFullGroupPath()
		if err != nil {
			return "", "", "", err
		}

		user.Groups = groupPath
	}
	_, originBackend := getOriginFromHost(host)

	name := ""
	if len(tokenNames) > 0 {
		name = strings.TrimSpace(tokenNames[0])
	}
	if name == "" {
		name = util.GenerateId()
	}
	jti := util.GetId(application.Owner, name)

	claims := Claims{
		User:      user,
		TokenType: "access-token",
		Nonce:     nonce,
		// FIXME: A workaround for custom claim by reusing `tag` in user info
		Tag:          user.Tag,
		Scope:        scope,
		Azp:          application.ClientId,
		Provider:     provider,
		SigninMethod: signinMethod,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    originBackend,
			Subject:   user.Id,
			Audience:  []string{application.ClientId},
			ExpiresAt: jwt.NewNumericDate(expireTime),
			NotBefore: jwt.NewNumericDate(nowTime),
			IssuedAt:  jwt.NewNumericDate(nowTime),
			ID:        jti,
		},
	}
	if authenticationContext != nil {
		claims.AuthenticationMethods = slices.Clone(authenticationContext.Amr)
		claims.AuthTime = authenticationContext.AuthTime
		claims.Acr = GetAuthenticationContextClass(authenticationContext.Amr)
	}
	if dpopJkt != "" {
		claims.Cnf = &DPoPConfirmation{JKT: dpopJkt}
	}

	// RFC 8707: Use resource as audience when provided
	if resource != "" {
		claims.Audience = []string{resource}
	} else if application.IsShared {
		claims.Audience = []string{application.ClientId + "-org-" + user.Owner}
	}

	var token *jwt.Token

	if application.TokenFormat == "" {
		application.TokenFormat = "JWT"
	}

	var jwtMethod jwt.SigningMethod

	if application.TokenSigningMethod == "RS256" {
		jwtMethod = jwt.SigningMethodRS256
	} else if application.TokenSigningMethod == "RS512" {
		jwtMethod = jwt.SigningMethodRS512
	} else if application.TokenSigningMethod == "ES256" {
		jwtMethod = jwt.SigningMethodES256
	} else if application.TokenSigningMethod == "ES512" {
		jwtMethod = jwt.SigningMethodES512
	} else if application.TokenSigningMethod == "ES384" {
		jwtMethod = jwt.SigningMethodES384
	} else {
		jwtMethod = jwt.SigningMethodRS256
	}

	// the JWT token length in "JWT-Empty" mode will be very short, as User object only has two properties: owner and name
	if application.TokenFormat == "JWT" {
		claimsWithoutThirdIdp := getClaimsWithoutThirdIdp(claims)

		token = jwt.NewWithClaims(jwtMethod, claimsWithoutThirdIdp)
	} else if application.TokenFormat == "JWT-Empty" {
		claimsShort := getShortClaims(claims)

		token = jwt.NewWithClaims(jwtMethod, claimsShort)
	} else if application.TokenFormat == "JWT-Custom" {
		claimsCustom, err := getClaimsCustom(claims, application.TokenFields, application.TokenAttributes)
		if err != nil {
			return "", "", "", err
		}

		token = jwt.NewWithClaims(jwtMethod, claimsCustom)
	} else if application.TokenFormat == "JWT-Standard" {
		claimsStandard := getStandardClaims(claims)

		token = jwt.NewWithClaims(jwtMethod, claimsStandard)
	} else {
		return "", "", "", fmt.Errorf("unknown application TokenFormat: %s", application.TokenFormat)
	}

	refreshClaims := getRefreshClaims(claims, refreshExpireTime)
	refreshToken := jwt.NewWithClaims(jwtMethod, refreshClaims)

	cert, err := getCertByApplication(application)
	if err != nil {
		return "", "", "", err
	}

	if cert == nil {
		if application.Cert == "" {
			return "", "", "", fmt.Errorf("The cert field of the application \"%s\" should not be empty", application.GetId())
		} else {
			return "", "", "", fmt.Errorf("The cert \"%s\" does not exist", application.Cert)
		}
	}

	var (
		tokenString        string
		refreshTokenString string
		key                interface{}
	)

	if strings.Contains(application.TokenSigningMethod, "RS") || application.TokenSigningMethod == "" {
		// RSA private key
		key, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cert.PrivateKey))
	} else if strings.Contains(application.TokenSigningMethod, "ES") {
		// ES private key
		key, err = jwt.ParseECPrivateKeyFromPEM([]byte(cert.PrivateKey))
	} else if strings.Contains(application.TokenSigningMethod, "Ed") {
		// Ed private key
		key, err = jwt.ParseEdPrivateKeyFromPEM([]byte(cert.PrivateKey))
	}
	if err != nil {
		return "", "", "", err
	}

	setJwtKeyID(cert.Name, token, refreshToken)
	tokenString, err = token.SignedString(key)
	if err != nil {
		return "", "", "", err
	}
	refreshTokenString, err = refreshToken.SignedString(key)

	return tokenString, refreshTokenString, name, err
}

func setJwtKeyID(keyID string, tokens ...*jwt.Token) {
	for _, token := range tokens {
		if token != nil {
			token.Header["kid"] = keyID
		}
	}
}

func ParseJwtTokenWithoutValidation(token string) (*jwt.Token, error) {
	t, _, err := jwt.NewParser().ParseUnverified(token, &Claims{})
	if err != nil {
		return nil, err
	}

	return t, nil
}

func ParseJwtToken(token string, cert *Cert) (*Claims, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		var (
			certificate interface{}
			err         error
		)

		if cert.Certificate == "" {
			return nil, fmt.Errorf("the certificate field should not be empty for the cert: %v", cert)
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			// RSA certificate
			certificate, err = jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
		} else if _, ok := token.Method.(*jwt.SigningMethodECDSA); ok {
			// ES certificate
			certificate, err = jwt.ParseECPublicKeyFromPEM([]byte(cert.Certificate))
		} else {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if err != nil {
			return nil, err
		}

		return certificate, nil
	})

	if t != nil {
		if claims, ok := t.Claims.(*Claims); ok && t.Valid {
			return claims, nil
		}
	}

	return nil, err
}

// ParseRefreshJwtToken validates and parses Casdoor's deliberately minimal
// refresh-token shape. Parsing it as Claims or ClaimsStandard leaves the
// embedded user pointer nil and makes downstream code prone to nil
// dereferences, so refresh credentials always use this dedicated boundary.
func ParseRefreshJwtToken(token string, cert *Cert) (*RefreshClaims, error) {
	t, err := jwt.ParseWithClaims(token, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		var (
			certificate interface{}
			err         error
		)

		if cert == nil || cert.Certificate == "" {
			return nil, fmt.Errorf("the certificate field should not be empty")
		}

		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			certificate, err = jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
		case *jwt.SigningMethodECDSA:
			certificate, err = jwt.ParseECPublicKeyFromPEM([]byte(cert.Certificate))
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if err != nil {
			return nil, err
		}
		return certificate, nil
	})
	if t != nil {
		if claims, ok := t.Claims.(*RefreshClaims); ok && t.Valid {
			if claims.TokenType != "refresh-token" {
				return nil, fmt.Errorf("unexpected token type %q", claims.TokenType)
			}
			return claims, nil
		}
	}
	if err == nil {
		err = fmt.Errorf("invalid refresh token")
	}
	return nil, err
}

func ParseRefreshJwtTokenByApplication(token string, application *Application) (*RefreshClaims, error) {
	cert, err := getCertByApplication(application)
	if err != nil {
		return nil, err
	}
	return ParseRefreshJwtToken(token, cert)
}

func ParseJwtTokenByApplication(token string, application *Application) (*Claims, error) {
	cert, err := getCertByApplication(application)
	if err != nil {
		return nil, err
	}

	return ParseJwtToken(token, cert)
}
