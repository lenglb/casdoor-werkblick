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

	"github.com/casdoor/casdoor/object"
)

type oauthClientAuthenticationInput struct {
	BasicPresent bool
	BasicId      string
	BasicSecret  string
	Query        url.Values
	Body         url.Values
}

func (c *ApiController) getOAuthClientAuthentication() (*object.OAuthClientAuthentication, *object.TokenError) {
	request := c.Ctx.Request
	authorizationHeader := request.Header.Get("Authorization")
	basicId, basicSecret, basicOk := request.BasicAuth()
	if authorizationHeader != "" && !basicOk {
		return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "invalid HTTP Basic client authentication")
	}

	if err := request.ParseForm(); err != nil {
		return nil, oauthClientAuthenticationRequestError(object.InvalidRequest, "invalid form body")
	}
	body := cloneUrlValues(request.PostForm)
	contentType := strings.ToLower(request.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/json") && len(c.Ctx.Input.RequestBody) != 0 {
		jsonBody, err := oauthAuthenticationJsonValues(c.Ctx.Input.RequestBody)
		if err != nil {
			return nil, oauthClientAuthenticationRequestError(object.InvalidRequest, "invalid JSON body")
		}
		for key, values := range jsonBody {
			if _, exists := body[key]; exists {
				return nil, oauthClientAuthenticationRequestError(object.InvalidRequest, fmt.Sprintf("duplicate %s parameter", key))
			}
			body[key] = values
		}
	}

	return resolveOAuthClientAuthentication(oauthClientAuthenticationInput{
		BasicPresent: basicOk,
		BasicId:      basicId,
		BasicSecret:  basicSecret,
		Query:        request.URL.Query(),
		Body:         body,
	})
}

func resolveOAuthClientAuthentication(input oauthClientAuthenticationInput) (*object.OAuthClientAuthentication, *object.TokenError) {
	queryClientId, queryClientIdPresent, tokenError := singleOAuthParameter(input.Query, "client_id")
	if tokenError != nil {
		return nil, tokenError
	}
	bodyClientId, bodyClientIdPresent, tokenError := singleOAuthParameter(input.Body, "client_id")
	if tokenError != nil {
		return nil, tokenError
	}
	if queryClientIdPresent && bodyClientIdPresent && queryClientId != bodyClientId {
		return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "conflicting client_id parameters")
	}

	querySecret, querySecretPresent, tokenError := singleOAuthParameter(input.Query, "client_secret")
	if tokenError != nil {
		return nil, tokenError
	}
	bodySecret, bodySecretPresent, tokenError := singleOAuthParameter(input.Body, "client_secret")
	if tokenError != nil {
		return nil, tokenError
	}
	queryAssertion, queryAssertionPresent, tokenError := singleOAuthParameter(input.Query, "client_assertion")
	if tokenError != nil {
		return nil, tokenError
	}
	bodyAssertion, bodyAssertionPresent, tokenError := singleOAuthParameter(input.Body, "client_assertion")
	if tokenError != nil {
		return nil, tokenError
	}
	queryAssertionType, queryAssertionTypePresent, tokenError := singleOAuthParameter(input.Query, "client_assertion_type")
	if tokenError != nil {
		return nil, tokenError
	}
	bodyAssertionType, bodyAssertionTypePresent, tokenError := singleOAuthParameter(input.Body, "client_assertion_type")
	if tokenError != nil {
		return nil, tokenError
	}

	// Client credentials in the URL can leak into logs, histories and proxy
	// metadata. They are never accepted, regardless of registered method.
	if querySecretPresent || queryAssertionPresent || queryAssertionTypePresent {
		_ = querySecret
		_ = queryAssertion
		_ = queryAssertionType
		return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "client credentials must not be sent in the query string")
	}

	requestClientId := bodyClientId
	if !bodyClientIdPresent {
		requestClientId = queryClientId
	}

	if input.BasicPresent {
		if input.BasicId == "" || input.BasicSecret == "" {
			return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "HTTP Basic client credentials are incomplete")
		}
		if bodySecretPresent || bodyAssertionPresent || bodyAssertionTypePresent {
			return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "multiple client authentication methods are not allowed")
		}
		if requestClientId != "" && requestClientId != input.BasicId {
			return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "client_id does not match HTTP Basic credentials")
		}
		return &object.OAuthClientAuthentication{
			Method:       object.ClientAuthMethodSecretBasic,
			ClientId:     input.BasicId,
			ClientSecret: input.BasicSecret,
		}, nil
	}

	if bodyAssertionPresent || bodyAssertionTypePresent {
		if bodySecretPresent {
			return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "multiple client authentication methods are not allowed")
		}
		if !bodyClientIdPresent || bodyClientId == "" || bodyAssertion == "" || bodyAssertionType != object.ClientAssertionTypeJwtBearer {
			return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "private_key_jwt client authentication is incomplete")
		}
		return &object.OAuthClientAuthentication{
			Method:              object.ClientAuthMethodPrivateKeyJwt,
			ClientId:            bodyClientId,
			ClientAssertion:     bodyAssertion,
			ClientAssertionType: bodyAssertionType,
		}, nil
	}

	if bodySecretPresent {
		if !bodyClientIdPresent || bodyClientId == "" || bodySecret == "" {
			return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "client_secret_post credentials are incomplete")
		}
		return &object.OAuthClientAuthentication{
			Method:       object.ClientAuthMethodSecretPost,
			ClientId:     bodyClientId,
			ClientSecret: bodySecret,
		}, nil
	}

	if requestClientId == "" {
		return nil, oauthClientAuthenticationRequestError(object.InvalidClient, "client_id is required")
	}
	return &object.OAuthClientAuthentication{
		Method:   object.ClientAuthMethodNone,
		ClientId: requestClientId,
	}, nil
}

func singleOAuthParameter(values url.Values, key string) (string, bool, *object.TokenError) {
	parameters, present := values[key]
	if !present {
		return "", false, nil
	}
	if len(parameters) != 1 {
		return "", true, oauthClientAuthenticationRequestError(object.InvalidRequest, fmt.Sprintf("duplicate %s parameter", key))
	}
	return parameters[0], true, nil
}

func oauthAuthenticationJsonValues(requestBody []byte) (url.Values, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(requestBody, &values); err != nil {
		return nil, err
	}

	result := url.Values{}
	for _, key := range []string{"client_id", "client_secret", "client_assertion", "client_assertion_type"} {
		rawValue, present := values[key]
		if !present {
			continue
		}
		var value string
		if err := json.Unmarshal(rawValue, &value); err != nil {
			return nil, fmt.Errorf("%s must be a string", key)
		}
		result[key] = []string{value}
	}
	return result, nil
}

func cloneUrlValues(values url.Values) url.Values {
	result := make(url.Values, len(values))
	for key, entries := range values {
		result[key] = append([]string(nil), entries...)
	}
	return result
}

func oauthClientAuthenticationRequestError(errorCode string, description string) *object.TokenError {
	return &object.TokenError{Error: errorCode, ErrorDescription: description}
}
