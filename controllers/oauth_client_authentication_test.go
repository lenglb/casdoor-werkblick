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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
)

func TestResolveOAuthClientAuthenticationPreservesCredentialTransport(t *testing.T) {
	tests := []struct {
		name       string
		input      oauthClientAuthenticationInput
		wantMethod string
		wantError  string
	}{
		{
			name: "basic credentials",
			input: oauthClientAuthenticationInput{
				BasicPresent: true,
				BasicId:      "client",
				BasicSecret:  "secret",
				Body:         url.Values{"grant_type": {"client_credentials"}},
			},
			wantMethod: object.ClientAuthMethodSecretBasic,
		},
		{
			name: "basic permits matching informational client id",
			input: oauthClientAuthenticationInput{
				BasicPresent: true,
				BasicId:      "client",
				BasicSecret:  "secret",
				Body:         url.Values{"client_id": {"client"}},
			},
			wantMethod: object.ClientAuthMethodSecretBasic,
		},
		{
			name: "basic rejects post secret",
			input: oauthClientAuthenticationInput{
				BasicPresent: true,
				BasicId:      "client",
				BasicSecret:  "secret",
				Body:         url.Values{"client_secret": {"secret"}},
			},
			wantError: object.InvalidClient,
		},
		{
			name: "basic rejects conflicting client id",
			input: oauthClientAuthenticationInput{
				BasicPresent: true,
				BasicId:      "client",
				BasicSecret:  "secret",
				Body:         url.Values{"client_id": {"other"}},
			},
			wantError: object.InvalidClient,
		},
		{
			name: "post credentials",
			input: oauthClientAuthenticationInput{
				Body: url.Values{
					"client_id":     {"client"},
					"client_secret": {"secret"},
				},
			},
			wantMethod: object.ClientAuthMethodSecretPost,
		},
		{
			name: "post requires body client id",
			input: oauthClientAuthenticationInput{
				Query: url.Values{"client_id": {"client"}},
				Body:  url.Values{"client_secret": {"secret"}},
			},
			wantError: object.InvalidClient,
		},
		{
			name: "query secret is rejected",
			input: oauthClientAuthenticationInput{
				Query: url.Values{
					"client_id":     {"client"},
					"client_secret": {"secret"},
				},
			},
			wantError: object.InvalidClient,
		},
		{
			name: "private key jwt credentials",
			input: oauthClientAuthenticationInput{
				Body: url.Values{
					"client_id":             {"client"},
					"client_assertion":      {"signed-assertion"},
					"client_assertion_type": {object.ClientAssertionTypeJwtBearer},
				},
			},
			wantMethod: object.ClientAuthMethodPrivateKeyJwt,
		},
		{
			name: "private key jwt rejects shared secret",
			input: oauthClientAuthenticationInput{
				Body: url.Values{
					"client_id":             {"client"},
					"client_secret":         {"secret"},
					"client_assertion":      {"signed-assertion"},
					"client_assertion_type": {object.ClientAssertionTypeJwtBearer},
				},
			},
			wantError: object.InvalidClient,
		},
		{
			name: "query assertion is rejected",
			input: oauthClientAuthenticationInput{
				Query: url.Values{
					"client_id":             {"client"},
					"client_assertion":      {"signed-assertion"},
					"client_assertion_type": {object.ClientAssertionTypeJwtBearer},
				},
			},
			wantError: object.InvalidClient,
		},
		{
			name: "public client without credentials",
			input: oauthClientAuthenticationInput{
				Body: url.Values{"client_id": {"public-client"}},
			},
			wantMethod: object.ClientAuthMethodNone,
		},
		{
			name: "duplicate credential parameter",
			input: oauthClientAuthenticationInput{
				Body: url.Values{
					"client_id":     {"client"},
					"client_secret": {"one", "two"},
				},
			},
			wantError: object.InvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authentication, tokenError := resolveOAuthClientAuthentication(test.input)
			if test.wantError != "" {
				if tokenError == nil || tokenError.Error != test.wantError {
					t.Fatalf("resolveOAuthClientAuthentication() = (%#v, %#v), want %s", authentication, tokenError, test.wantError)
				}
				return
			}
			if tokenError != nil || authentication == nil || authentication.Method != test.wantMethod {
				t.Fatalf("resolveOAuthClientAuthentication() = (%#v, %#v), want method %s", authentication, tokenError, test.wantMethod)
			}
		})
	}
}

func TestOAuthAuthenticationJsonValuesTracksEmptyCredentials(t *testing.T) {
	values, err := oauthAuthenticationJsonValues([]byte(`{"client_id":"client","client_secret":""}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := values["client_secret"]; !present {
		t.Fatal("empty client_secret presence was lost")
	}
}

func TestGetOAuthClientAuthenticationReadsActualHttpTransport(t *testing.T) {
	postValues := url.Values{
		"client_id":     {"post-client"},
		"client_secret": {"post-secret"},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader(postValues.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := beegocontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), request)
	controller := &ApiController{}
	controller.Ctx = ctx

	authentication, tokenError := controller.getOAuthClientAuthentication()
	if tokenError != nil || authentication == nil || authentication.Method != object.ClientAuthMethodSecretPost {
		t.Fatalf("form transport = (%#v, %#v), want client_secret_post", authentication, tokenError)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token?client_secret=leaked", strings.NewReader("client_id=client"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx = beegocontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), request)
	controller = &ApiController{}
	controller.Ctx = ctx
	if authentication, tokenError = controller.getOAuthClientAuthentication(); tokenError == nil || tokenError.Error != object.InvalidClient {
		t.Fatalf("query credential = (%#v, %#v), want invalid_client", authentication, tokenError)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/login/oauth/access_token", strings.NewReader("grant_type=client_credentials"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("basic-client", "basic-secret")
	ctx = beegocontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), request)
	controller = &ApiController{}
	controller.Ctx = ctx
	if authentication, tokenError = controller.getOAuthClientAuthentication(); tokenError != nil || authentication.Method != object.ClientAuthMethodSecretBasic {
		t.Fatalf("basic transport = (%#v, %#v), want client_secret_basic", authentication, tokenError)
	}
}
