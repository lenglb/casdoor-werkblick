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
	"crypto/subtle"
)

const (
	ClientAuthMethodNone          = "none"
	ClientAuthMethodSecretBasic   = "client_secret_basic"
	ClientAuthMethodSecretPost    = "client_secret_post"
	ClientAuthMethodPrivateKeyJwt = "private_key_jwt"
	ClientAssertionTypeJwtBearer  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// OAuthClientAuthentication describes both the credentials and their transport.
// Method is derived from the HTTP request by the controller; it is never copied
// from application configuration. Keeping the two values separate is what makes
// downgrade detection possible.
type OAuthClientAuthentication struct {
	Method              string
	ClientId            string
	ClientSecret        string
	ClientAssertion     string
	ClientAssertionType string
}

// AuthenticateOAuthClient enforces the application's registered token endpoint
// authentication method exactly. It intentionally returns invalid_client for all
// credential failures so callers do not disclose client metadata.
func AuthenticateOAuthClient(authentication *OAuthClientAuthentication, host string) (*Application, *TokenError, error) {
	if authentication == nil || authentication.ClientId == "" {
		return nil, invalidOAuthClient("client authentication is required"), nil
	}

	application, err := GetApplicationByClientId(authentication.ClientId)
	if err != nil {
		return nil, nil, err
	}
	if application == nil {
		return nil, invalidOAuthClient("client authentication failed"), nil
	}

	if tokenError := validateOAuthClientAuthentication(application, authentication, host); tokenError != nil {
		return nil, tokenError, nil
	}
	return application, nil, nil
}

func validateOAuthClientAuthentication(application *Application, authentication *OAuthClientAuthentication, host string) *TokenError {
	if application == nil || authentication == nil || authentication.ClientId == "" || authentication.ClientId != application.ClientId {
		return invalidOAuthClient("client authentication failed")
	}
	if authentication.Method != application.GetTokenEndpointAuthMethod() {
		return invalidOAuthClient("token endpoint authentication method does not match client registration")
	}

	switch authentication.Method {
	case ClientAuthMethodSecretBasic, ClientAuthMethodSecretPost:
		if authentication.ClientSecret == "" || authentication.ClientAssertion != "" || authentication.ClientAssertionType != "" {
			return invalidOAuthClient("client authentication failed")
		}
		if application.ClientSecret == "" || subtle.ConstantTimeCompare([]byte(application.ClientSecret), []byte(authentication.ClientSecret)) != 1 {
			return invalidOAuthClient("client authentication failed")
		}
	case ClientAuthMethodPrivateKeyJwt:
		if authentication.ClientSecret != "" || authentication.ClientAssertion == "" || authentication.ClientAssertionType != ClientAssertionTypeJwtBearer {
			return invalidOAuthClient("client authentication failed")
		}
		ok, err := ValidateClientAssertionForApplication(authentication.ClientAssertion, application, host)
		if err != nil || !ok {
			return invalidOAuthClient("client assertion is invalid")
		}
	case ClientAuthMethodNone:
		if authentication.ClientSecret != "" || authentication.ClientAssertion != "" || authentication.ClientAssertionType != "" {
			return invalidOAuthClient("public clients must not send client credentials")
		}
	default:
		return invalidOAuthClient("unsupported token endpoint authentication method")
	}

	return nil
}

// EffectiveClientSecret is used only by older grant implementations after the
// central authentication boundary has succeeded. It must never be used to decide
// which endpoint authentication method a request used.
func (authentication *OAuthClientAuthentication) EffectiveClientSecret(application *Application) string {
	if authentication == nil || application == nil || authentication.Method == ClientAuthMethodNone {
		return ""
	}
	return application.ClientSecret
}

func invalidOAuthClient(description string) *TokenError {
	return &TokenError{Error: InvalidClient, ErrorDescription: description}
}
