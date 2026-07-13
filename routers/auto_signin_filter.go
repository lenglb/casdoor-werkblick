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

package routers

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/mcpself"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func AutoSigninFilter(ctx *context.Context) {
	urlPath := ctx.Request.URL.Path
	if strings.HasPrefix(urlPath, "/api/login/oauth/access_token") {
		return
	}
	if urlPath == "/api/mcp" {
		var req mcpself.McpRequest
		if err := json.Unmarshal(ctx.Input.RequestBody, &req); err == nil {
			if req.Method == "initialize" || req.Method == "notifications/initialized" || req.Method == "ping" || req.Method == "tools/list" {
				return
			}
		}
	}
	//if getSessionUser(ctx) != "" {
	//	return
	//}

	// GET parameter like "/page?access_token=123" or
	// HTTP Bearer token like "Authorization: Bearer 123"
	accessToken := ctx.Input.Query("accessToken")
	if accessToken == "" {
		accessToken = ctx.Input.Query("access_token")
	}
	if accessToken == "" {
		accessToken = parseBearerToken(ctx)
	}

	if accessToken != "" {
		token, err := object.GetTokenByAccessToken(accessToken)
		if err != nil {
			responseError(ctx, err.Error())
			return
		}

		if token == nil {
			responseError(ctx, "Access token doesn't exist in database")
			return
		}

		isExpired, expireTime := util.IsTokenExpired(token.CreatedTime, token.ExpiresIn)
		if isExpired {
			responseError(ctx, fmt.Sprintf("Access token has expired, expireTime = %s", expireTime))
			return
		}

		// Validate DPoP proof for DPoP-bound tokens (RFC 9449).
		if token.TokenType == "DPoP" {
			authorizationParts := strings.SplitN(ctx.Request.Header.Get("Authorization"), " ", 2)
			if len(authorizationParts) != 2 || authorizationParts[0] != "DPoP" || authorizationParts[1] != accessToken {
				responseDPoPUnauthorized(ctx, "invalid_token", "DPoP-bound access tokens require the DPoP authorization scheme")
				return
			}
			dpopProof := ctx.Request.Header.Get("DPoP")
			if dpopProof == "" {
				responseDPoPUnauthorized(ctx, "invalid_dpop_proof", "DPoP proof header is required")
				return
			}
			htu := object.GetDPoPHtu(ctx.Request.Host, ctx.Request.URL.EscapedPath())
			jkt, dpopErr := object.ValidateDPoPProof(dpopProof, ctx.Request.Method, htu, accessToken)
			if dpopErr != nil {
				responseDPoPUnauthorized(ctx, "invalid_dpop_proof", "DPoP proof validation failed")
				return
			}
			if subtle.ConstantTimeCompare([]byte(jkt), []byte(token.DPoPJkt)) != 1 {
				responseDPoPUnauthorized(ctx, "invalid_token", "DPoP proof key binding mismatch")
				return
			}
		}

		application, err := object.GetApplicationByUserId(fmt.Sprintf("app/%s", token.Application))
		if err != nil {
			responseError(ctx, err.Error())
			return
		}
		if application == nil {
			responseError(ctx, fmt.Sprintf("No application is found for userId: app/%s", token.Application))
			return
		}

		var userId string
		if token.GrantType == "client_credentials" {
			userId = fmt.Sprintf("app/%s", token.Application)
		} else {
			userId = util.GetId(token.Organization, token.User)
		}
		// Bearer/DPoP authentication is request-scoped. Promoting it into the
		// browser session would turn a proof-bound API token into a reusable
		// cookie session that no longer requires the DPoP proof.
		ctx.Input.SetData("tokenAuthenticatedUserId", userId)
		ctx.Input.SetData("tokenAuthenticatedScope", token.Scope)
		ctx.Input.SetData("tokenAuthenticatedAud", application.ClientId)
		ctx.Input.SetData("tokenAuthenticatedAccessToken", accessToken)
		return
	}

	// "/page?clientId=123&clientSecret=456"
	userId, err := getUsernameByClientIdSecret(ctx)
	if err != nil {
		responseError(ctx, err.Error())
		return
	}
	if userId != "" {
		setSessionUser(ctx, userId)
		return
	}

	// "/page?accessKey=123&accessSecret=456"
	userId, err = getUsernameByAccessKey(ctx)
	if err != nil {
		responseError(ctx, err.Error())
		return
	}
	if userId != "" {
		setSessionUser(ctx, userId)
		return
	}

	// "/page?username=built-in/admin&password=123"
	userId = ctx.Input.Query("username")
	password := ctx.Input.Query("password")
	if userId != "" && password != "" && ctx.Input.Query("grant_type") == "" {
		owner, name, err := util.GetOwnerAndNameFromIdWithError(userId)
		if err != nil {
			responseError(ctx, err.Error())
			return
		}

		_, err = object.CheckUserPassword(owner, name, password, "en")
		if err != nil {
			responseError(ctx, err.Error())
			return
		}

		setSessionUser(ctx, userId)
	}
}

func responseDPoPUnauthorized(ctx *context.Context, errorCode string, description string) {
	ctx.Output.Header("WWW-Authenticate", fmt.Sprintf(`DPoP error=%q, error_description=%q`, errorCode, description))
	ctx.Output.SetStatus(http.StatusUnauthorized)
	responseError(ctx, description)
}
