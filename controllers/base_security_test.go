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
	"testing"

	beegocontext "github.com/beego/beego/v2/server/web/context"
)

func TestGetSessionUsernameUsesRequestScopedTokenIdentity(t *testing.T) {
	ctx := beegocontext.NewContext()
	ctx.Reset(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/get-account", nil))
	ctx.Input.SetData("tokenAuthenticatedUserId", "built-in/alice")
	controller := &ApiController{}
	controller.Ctx = ctx

	if got := controller.GetSessionUsername(); got != "built-in/alice" {
		t.Fatalf("GetSessionUsername() = %q, want request-scoped token identity", got)
	}
	if ctx.Input.CruSession != nil {
		t.Fatal("request-scoped identity unexpectedly created a browser session")
	}
}
