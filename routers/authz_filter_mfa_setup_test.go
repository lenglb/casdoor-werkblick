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

package routers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	beegocontext "github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func validRestrictedMfaSetupPending(now time.Time) object.PendingAuthentication {
	return object.PendingAuthentication{
		Context: object.AuthenticationContext{
			Subject:  "built-in/alice",
			AuthTime: now.Add(-time.Minute).Unix(),
			Amr:      []string{"pwd"},
		},
		FlowType:      "login",
		ApplicationId: "built-in/application-built-in",
		TransactionId: "mfa-setup-transaction",
		CreatedAt:     now.Add(-time.Minute).Unix(),
		ExpiresAt:     now.Add(time.Minute).Unix(),
	}
}

func newRestrictedMfaSetupRequest(t *testing.T, method, target string, form url.Values) *beegocontext.Context {
	t.Helper()
	var request *http.Request
	if form == nil {
		request = httptest.NewRequest(method, target, nil)
	} else {
		request = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response := httptest.NewRecorder()
	ctx := beegocontext.NewContext()
	ctx.Reset(response, request)
	return ctx
}

func TestRestrictedMfaSetupSessionActivation(t *testing.T) {
	tests := []struct {
		name     string
		setup    interface{}
		username interface{}
		want     bool
	}{
		{name: "no setup marker", setup: nil, username: nil, want: false},
		{name: "restricted continuation", setup: "built-in/alice", username: "", want: true},
		{name: "missing username", setup: "built-in/alice", username: nil, want: true},
		{name: "malformed username fails closed", setup: "built-in/alice", username: 42, want: true},
		{name: "normal session takes precedence", setup: "built-in/alice", username: "built-in/alice", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRestrictedMfaSetupSessionActive(tt.setup, tt.username); got != tt.want {
				t.Fatalf("isRestrictedMfaSetupSessionActive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUsernameUsesRequestScopedTokenIdentity(t *testing.T) {
	ctx := newRestrictedMfaSetupRequest(t, http.MethodGet, "/api/get-account", nil)
	ctx.Input.SetData("tokenAuthenticatedUserId", "built-in/alice")

	if got := getUsername(ctx); got != "built-in/alice" {
		t.Fatalf("getUsername() = %q, want request-scoped token identity", got)
	}
	if ctx.Input.CruSession != nil {
		t.Fatal("request-scoped identity unexpectedly created a browser session")
	}
}

func TestParseRestrictedMfaSetupSession(t *testing.T) {
	now := time.Now()
	pending := validRestrictedMfaSetupPending(now)
	session, err := parseRestrictedMfaSetupSession("built-in/alice", util.StructToJson(pending))
	if err != nil {
		t.Fatalf("parseRestrictedMfaSetupSession() error = %v", err)
	}
	if session.UserId != "built-in/alice" || session.UserOwner != "built-in" || session.UserName != "alice" {
		t.Fatalf("parsed user binding = %#v", session)
	}
	if session.Pending.ApplicationId != pending.ApplicationId {
		t.Fatalf("application binding = %q, want %q", session.Pending.ApplicationId, pending.ApplicationId)
	}
}

func TestParseRestrictedMfaSetupSessionFailsClosed(t *testing.T) {
	now := time.Now()
	valid := validRestrictedMfaSetupPending(now)

	tests := []struct {
		name    string
		setup   interface{}
		pending interface{}
	}{
		{name: "setup user wrong type", setup: 42, pending: util.StructToJson(valid)},
		{name: "setup user empty", setup: "", pending: util.StructToJson(valid)},
		{name: "setup user noncanonical", setup: " built-in/alice", pending: util.StructToJson(valid)},
		{name: "setup user malformed", setup: "alice", pending: util.StructToJson(valid)},
		{name: "pending missing", setup: "built-in/alice", pending: nil},
		{name: "pending wrong type", setup: "built-in/alice", pending: 42},
		{name: "pending malformed", setup: "built-in/alice", pending: "{"},
		{name: "pending expired", setup: "built-in/alice", pending: func() string {
			value := valid
			value.CreatedAt = now.Add(-2 * time.Minute).Unix()
			value.ExpiresAt = now.Add(-time.Minute).Unix()
			return util.StructToJson(value)
		}()},
		{name: "pending user mismatch", setup: "built-in/alice", pending: func() string {
			value := valid
			value.Context.Subject = "built-in/bob"
			return util.StructToJson(value)
		}()},
		{name: "pending application malformed", setup: "built-in/alice", pending: func() string {
			value := valid
			value.ApplicationId = "application-built-in"
			return util.StructToJson(value)
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseRestrictedMfaSetupSession(tt.setup, tt.pending); err == nil {
				t.Fatal("parseRestrictedMfaSetupSession() unexpectedly succeeded")
			}
		})
	}
}

func TestRestrictedMfaSetupRequestAllowlist(t *testing.T) {
	now := time.Now()
	pending := validRestrictedMfaSetupPending(now)
	session, err := parseRestrictedMfaSetupSession("built-in/alice", util.StructToJson(pending))
	if err != nil {
		t.Fatalf("parseRestrictedMfaSetupSession() error = %v", err)
	}

	boundUser := url.Values{"owner": {"built-in"}, "name": {"alice"}}
	boundVerification := url.Values{
		"method":        {"mfaSetup"},
		"checkUser":     {"alice"},
		"applicationId": {pending.ApplicationId},
	}
	tests := []struct {
		name   string
		method string
		target string
		form   url.Values
		want   bool
	}{
		{name: "account", method: http.MethodGet, target: "/api/get-account", want: true},
		{name: "account wrong method", method: http.MethodPost, target: "/api/get-account", form: url.Values{}, want: false},
		{name: "bound application", method: http.MethodGet, target: "/api/get-application?id=" + url.QueryEscape(pending.ApplicationId), want: true},
		{name: "different application", method: http.MethodGet, target: "/api/get-application?id=built-in%2Fother", want: false},
		{name: "MFA initiate", method: http.MethodPost, target: "/api/mfa/setup/initiate", form: boundUser, want: true},
		{name: "MFA verify", method: http.MethodPost, target: "/api/mfa/setup/verify", form: boundUser, want: true},
		{name: "MFA enable", method: http.MethodPost, target: "/api/mfa/setup/enable", form: boundUser, want: true},
		{name: "different MFA user", method: http.MethodPost, target: "/api/mfa/setup/verify", form: url.Values{"owner": {"built-in"}, "name": {"bob"}}, want: false},
		{name: "user only in query", method: http.MethodPost, target: "/api/mfa/setup/verify?owner=built-in&name=alice", form: url.Values{}, want: false},
		{name: "bound verification", method: http.MethodPost, target: "/api/send-verification-code", form: boundVerification, want: true},
		{name: "verification wrong method", method: http.MethodPost, target: "/api/send-verification-code", form: url.Values{"method": {"mfaAuth"}, "checkUser": {"alice"}, "applicationId": {pending.ApplicationId}}, want: false},
		{name: "verification wrong user", method: http.MethodPost, target: "/api/send-verification-code", form: url.Values{"method": {"mfaSetup"}, "checkUser": {"bob"}, "applicationId": {pending.ApplicationId}}, want: false},
		{name: "verification wrong application", method: http.MethodPost, target: "/api/send-verification-code", form: url.Values{"method": {"mfaSetup"}, "checkUser": {"alice"}, "applicationId": {"built-in/other"}}, want: false},
		{name: "public endpoint remains denied", method: http.MethodGet, target: "/api/health", want: false},
		{name: "unrelated authenticated endpoint remains denied", method: http.MethodGet, target: "/api/get-users", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newRestrictedMfaSetupRequest(t, tt.method, tt.target, tt.form)
			if got := isRestrictedMfaSetupRequestAllowed(ctx, session, tt.method, ctx.Request.URL.Path); got != tt.want {
				t.Fatalf("isRestrictedMfaSetupRequestAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
