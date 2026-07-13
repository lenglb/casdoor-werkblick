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
	"strings"
	"time"

	"github.com/casdoor/casdoor/util"
)

// DynamicClientRegistrationRequest represents an RFC 7591 client registration request
type DynamicClientRegistrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectUris            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	LogoUri                 string   `json:"logo_uri,omitempty"`
	ClientUri               string   `json:"client_uri,omitempty"`
	PolicyUri               string   `json:"policy_uri,omitempty"`
	TosUri                  string   `json:"tos_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// DynamicClientRegistrationResponse represents an RFC 7591/7592 client registration response
type DynamicClientRegistrationResponse struct {
	ClientId                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIdIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectUris            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	LogoUri                 string   `json:"logo_uri,omitempty"`
	ClientUri               string   `json:"client_uri,omitempty"`
	PolicyUri               string   `json:"policy_uri,omitempty"`
	TosUri                  string   `json:"tos_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	RegistrationClientUri   string   `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
}

// DcrError represents an RFC 7591/7592 error response
type DcrError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

const maxDynamicClientScopeTokenLength = 128

// normalizeDynamicClientScopes accepts only canonical, literal OAuth scope
// tokens. DCR clients cannot introduce regex patterns into an application's
// allowlist, and the normalized response always mirrors the stored contract.
func normalizeDynamicClientScopes(scope string) ([]*ScopeItem, string, error) {
	if scope == "" {
		return []*ScopeItem{}, "", nil
	}
	if strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, "\t\r\n") {
		return nil, "", fmt.Errorf("scope must be a single-space-separated list of tokens")
	}

	tokens := strings.Split(scope, " ")
	items := make([]*ScopeItem, 0, len(tokens))
	normalized := make([]string, 0, len(tokens))
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if !isSafeDynamicClientScopeToken(token) {
			return nil, "", fmt.Errorf("scope token %q is empty, unsafe, or not a literal", token)
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		items = append(items, &ScopeItem{Name: token})
		normalized = append(normalized, token)
	}
	return items, strings.Join(normalized, " "), nil
}

func isSafeDynamicClientScopeToken(token string) bool {
	if token == "" || len(token) > maxDynamicClientScopeTokenLength {
		return false
	}
	for _, character := range token {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '_', ':', '/', '-':
			continue
		default:
			return false
		}
	}
	return true
}

func dynamicClientScopeString(scopes []*ScopeItem) string {
	names := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope != nil && scope.Name != "" {
			names = append(names, scope.Name)
		}
	}
	return strings.Join(names, " ")
}

func validateDynamicClientOAuthMetadata(grantTypes []string, responseTypes []string) error {
	if err := ValidateOAuthGrantTypes(grantTypes); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(responseTypes))
	for _, responseType := range responseTypes {
		grantType, ok := requiredGrantForOAuthResponseType(responseType)
		if !ok {
			return fmt.Errorf("unsupported OAuth response type: %q", responseType)
		}
		if _, exists := seen[responseType]; exists {
			return fmt.Errorf("OAuth response type is duplicated: %q", responseType)
		}
		seen[responseType] = struct{}{}
		if !IsGrantTypeValid(grantType, grantTypes) {
			return fmt.Errorf("OAuth response type %q requires grant type %q", responseType, grantType)
		}
	}
	return nil
}

// RegisterDynamicClient creates a new application based on DCR request (RFC 7591)
func RegisterDynamicClient(req *DynamicClientRegistrationRequest, organization string, registrationClientUri string) (*DynamicClientRegistrationResponse, *DcrError, error) {
	// Validate organization exists and has DCR enabled
	org, err := GetOrganization(util.GetId("admin", organization))
	if err != nil {
		return nil, nil, err
	}
	if org == nil {
		return nil, &DcrError{
			Error:            "invalid_client_metadata",
			ErrorDescription: "organization not found",
		}, nil
	}

	// Check if DCR is enabled for this organization
	if org.DcrPolicy == "" || org.DcrPolicy == "disabled" {
		return nil, &DcrError{
			Error:            "invalid_client_metadata",
			ErrorDescription: "dynamic client registration is disabled for this organization",
		}, nil
	}

	// Validate required fields
	if len(req.RedirectUris) == 0 {
		return nil, &DcrError{
			Error:            "invalid_redirect_uri",
			ErrorDescription: "redirect_uris is required and must contain at least one URI",
		}, nil
	}
	scopeItems, normalizedScope, scopeErr := normalizeDynamicClientScopes(req.Scope)
	if scopeErr != nil {
		return nil, &DcrError{
			Error:            "invalid_client_metadata",
			ErrorDescription: scopeErr.Error(),
		}, nil
	}
	req.Scope = normalizedScope
	if metadataErr := validateDynamicClientOAuthMetadata(req.GrantTypes, req.ResponseTypes); metadataErr != nil {
		return nil, &DcrError{
			Error:            "invalid_client_metadata",
			ErrorDescription: metadataErr.Error(),
		}, nil
	}

	// Set defaults
	if req.ClientName == "" {
		clientIdPrefix := util.GenerateClientId()
		if len(clientIdPrefix) > 8 {
			clientIdPrefix = clientIdPrefix[:8]
		}
		req.ClientName = fmt.Sprintf("DCR Client %s", clientIdPrefix)
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	switch req.TokenEndpointAuthMethod {
	case "none", "client_secret_basic", "client_secret_post", "private_key_jwt":
	default:
		return nil, &DcrError{
			Error:            "invalid_client_metadata",
			ErrorDescription: "unsupported token_endpoint_auth_method",
		}, nil
	}
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}

	// Generate unique application name
	randomName := util.GetRandomName()
	appName := fmt.Sprintf("dcr_%s", randomName)

	// Inherit providers, signin methods, and branding from the organization's default application
	// so that DCR-registered apps have a working sign-in method and correct branding out of the box.
	var inheritedProviders []*ProviderItem
	var inheritedSigninMethods []*SigninMethod
	var inheritedLogo, inheritedFooterHtml, inheritedFormCss string
	var inheritedThemeData *ThemeData
	var inheritedSigninItems []*SigninItem
	var inheritedEnableSigninSession, inheritedEnableWebAuthn bool
	defaultApp, err := GetDefaultApplication(util.GetId("admin", organization))
	if err == nil && defaultApp != nil {
		inheritedProviders = defaultApp.Providers
		inheritedSigninMethods = defaultApp.SigninMethods
		inheritedLogo = defaultApp.Logo
		inheritedThemeData = defaultApp.ThemeData
		inheritedFooterHtml = defaultApp.FooterHtml
		inheritedFormCss = defaultApp.FormCss
		inheritedSigninItems = defaultApp.SigninItems
		inheritedEnableSigninSession = defaultApp.EnableSigninSession
		inheritedEnableWebAuthn = defaultApp.EnableWebAuthn
	}

	// Create Application object
	// Note: DCR applications are created under "admin" owner by default
	// This can be made configurable in future versions
	clientId := util.GenerateClientId()
	clientSecret := ""
	if (&Application{TokenEndpointAuthMethod: req.TokenEndpointAuthMethod}).UsesClientSecret() {
		clientSecret = util.GenerateClientSecret()
	}
	registrationAccessToken := util.GenerateClientSecret()
	createdTime := util.GetCurrentTime()

	application := &Application{
		Owner:                   "admin",
		Name:                    appName,
		Organization:            organization,
		CreatedTime:             createdTime,
		DisplayName:             req.ClientName,
		Category:                "Agent",
		Type:                    "MCP",
		Scopes:                  scopeItems,
		Logo:                    firstNonEmpty(req.LogoUri, inheritedLogo),
		ThemeData:               inheritedThemeData,
		FooterHtml:              inheritedFooterHtml,
		FormCss:                 inheritedFormCss,
		SigninItems:             inheritedSigninItems,
		HomepageUrl:             req.ClientUri,
		ClientId:                clientId,
		ClientSecret:            clientSecret,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RedirectUris:            req.RedirectUris,
		GrantTypes:              req.GrantTypes,
		EnablePassword:          true,
		EnableSignUp:            false,
		DisableSignin:           false,
		EnableSigninSession:     inheritedEnableSigninSession,
		EnableCodeSignin:        true,
		EnableAutoSignin:        false,
		EnableWebAuthn:          inheritedEnableWebAuthn,
		TokenFormat:             "JWT",
		ExpireInHours:           168,
		RefreshExpireInHours:    168,
		CookieExpireInHours:     720,
		FormOffset:              2,
		Tags:                    []string{"dcr"},
		TermsOfUse:              req.TosUri,
		Providers:               inheritedProviders,
		SigninMethods:           inheritedSigninMethods,
		RegistrationAccessToken: registrationAccessToken,
	}

	// Add the application
	affected, err := AddApplication(application)
	if err != nil {
		return nil, nil, err
	}
	if !affected {
		return nil, &DcrError{
			Error:            "invalid_client_metadata",
			ErrorDescription: "failed to create client application",
		}, nil
	}

	// Build response
	response := &DynamicClientRegistrationResponse{
		ClientId:                clientId,
		ClientSecret:            clientSecret,
		ClientIdIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              req.ClientName,
		RedirectUris:            req.RedirectUris,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		ApplicationType:         req.ApplicationType,
		Contacts:                req.Contacts,
		LogoUri:                 req.LogoUri,
		ClientUri:               req.ClientUri,
		PolicyUri:               req.PolicyUri,
		TosUri:                  req.TosUri,
		Scope:                   dynamicClientScopeString(application.Scopes),
		RegistrationClientUri:   fmt.Sprintf("%s/%s", registrationClientUri, clientId),
		RegistrationAccessToken: registrationAccessToken,
	}

	return response, nil, nil
}

// GetDynamicClientByToken finds a DCR application by clientId and validates the registration access token
func GetDynamicClientByToken(clientId, bearerToken string) (*Application, *DcrError) {
	application, err := GetApplicationByClientId(clientId)
	if err != nil {
		return nil, &DcrError{Error: "server_error", ErrorDescription: err.Error()}
	}
	if application == nil {
		return nil, &DcrError{Error: "invalid_token", ErrorDescription: "client not found"}
	}
	if application.RegistrationAccessToken == "" || application.RegistrationAccessToken != bearerToken {
		return nil, &DcrError{Error: "invalid_token", ErrorDescription: "invalid registration access token"}
	}
	return application, nil
}

// GetDynamicClientRegistrationResponse builds a RFC 7592 read response from an application
func GetDynamicClientRegistrationResponse(app *Application, registrationClientUri string) *DynamicClientRegistrationResponse {
	return &DynamicClientRegistrationResponse{
		ClientId:                app.ClientId,
		ClientSecret:            app.ClientSecret,
		ClientIdIssuedAt:        0,
		ClientSecretExpiresAt:   0,
		ClientName:              app.DisplayName,
		RedirectUris:            app.RedirectUris,
		GrantTypes:              app.GrantTypes,
		TokenEndpointAuthMethod: app.GetTokenEndpointAuthMethod(),
		ApplicationType:         "web",
		LogoUri:                 app.Logo,
		ClientUri:               app.HomepageUrl,
		TosUri:                  app.TermsOfUse,
		Scope:                   dynamicClientScopeString(app.Scopes),
		RegistrationClientUri:   fmt.Sprintf("%s/%s", registrationClientUri, app.ClientId),
		RegistrationAccessToken: app.RegistrationAccessToken,
	}
}

// UpdateDynamicClient applies a RFC 7592 PUT update to a DCR application
func UpdateDynamicClient(app *Application, req *DynamicClientRegistrationRequest) (*DynamicClientRegistrationResponse, *DcrError, error) {
	if len(req.RedirectUris) == 0 {
		return nil, &DcrError{
			Error:            "invalid_redirect_uri",
			ErrorDescription: "redirect_uris is required and must contain at least one URI",
		}, nil
	}
	scopeItems, _, scopeErr := normalizeDynamicClientScopes(req.Scope)
	if scopeErr != nil {
		return nil, &DcrError{Error: "invalid_client_metadata", ErrorDescription: scopeErr.Error()}, nil
	}
	effectiveGrantTypes := app.GrantTypes
	if req.GrantTypes != nil {
		effectiveGrantTypes = req.GrantTypes
	}
	responseTypes := req.ResponseTypes
	if responseTypes == nil {
		responseTypes = []string{}
	}
	if metadataErr := validateDynamicClientOAuthMetadata(effectiveGrantTypes, responseTypes); metadataErr != nil {
		return nil, &DcrError{Error: "invalid_client_metadata", ErrorDescription: metadataErr.Error()}, nil
	}
	if req.TokenEndpointAuthMethod != "" {
		switch req.TokenEndpointAuthMethod {
		case "none", "client_secret_basic", "client_secret_post", "private_key_jwt":
		default:
			return nil, &DcrError{Error: "invalid_client_metadata", ErrorDescription: "unsupported token_endpoint_auth_method"}, nil
		}
		app.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
		if !app.UsesClientSecret() {
			app.ClientSecret = ""
		} else if app.ClientSecret == "" {
			app.ClientSecret = util.GenerateClientSecret()
		}
	}

	app.DisplayName = firstNonEmpty(req.ClientName, app.DisplayName)
	app.RedirectUris = req.RedirectUris
	app.Scopes = scopeItems
	if req.GrantTypes != nil {
		app.GrantTypes = append([]string{}, req.GrantTypes...)
	}
	if req.LogoUri != "" {
		app.Logo = req.LogoUri
	}
	if req.ClientUri != "" {
		app.HomepageUrl = req.ClientUri
	}
	if req.TosUri != "" {
		app.TermsOfUse = req.TosUri
	}

	_, err := UpdateApplication(util.GetId(app.Owner, app.Name), app, true, "", nil)
	if err != nil {
		return nil, nil, err
	}

	return GetDynamicClientRegistrationResponse(app, ""), nil, nil
}

// DeleteDynamicClient removes a DCR-registered application
func DeleteDynamicClient(app *Application) *DcrError {
	affected, err := DeleteApplication(app)
	if err != nil {
		return &DcrError{Error: "server_error", ErrorDescription: err.Error()}
	}
	if !affected {
		return &DcrError{Error: "server_error", ErrorDescription: "failed to delete client"}
	}
	return nil
}
