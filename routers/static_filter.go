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
	"compress/gzip"
	stdcontext "context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web/context"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var (
	oldStaticBaseUrl = "https://cdn.casbin.org"
	newStaticBaseUrl = conf.GetConfigString("staticBaseUrl")
	enableGzip       = conf.GetConfigBool("enableGzip")
	frontendBaseDir  = conf.GetConfigString("frontendBaseDir")
)

func getWebBuildFolder() string {
	path := "web/build"
	if util.FileExist(filepath.Join(path, "index.html")) || frontendBaseDir == "" {
		return path
	}

	if util.FileExist(filepath.Join(frontendBaseDir, "index.html")) {
		return frontendBaseDir
	}

	path = filepath.Join(frontendBaseDir, "web/build")
	if util.FileExist(filepath.Join(path, "index.html")) {
		return path
	}

	casdoorDir := filepath.Join(filepath.Dir(frontendBaseDir), "casdoor")
	if util.FileExist(filepath.Join(casdoorDir, "index.html")) {
		return casdoorDir
	}
	if util.FileExist(filepath.Join(casdoorDir, "web/build", "index.html")) {
		return filepath.Join(casdoorDir, "web/build")
	}

	return path
}

func pendingAuthenticationBlocksAutoSignin(ctx *context.Context) (bool, error) {
	value := ctx.Input.CruSession.Get(stdcontext.Background(), object.PendingAuthenticationSessionKey)
	if value == nil {
		return false, nil
	}

	serialized, ok := value.(string)
	if ok && strings.TrimSpace(serialized) != "" {
		var pending object.PendingAuthentication
		if err := util.JsonToStruct(serialized, &pending); err == nil {
			if _, err = pending.Preserve(); err == nil {
				return true, nil
			}
		}
	}

	if err := ctx.Input.CruSession.Delete(stdcontext.Background(), object.PendingAuthenticationSessionKey); err != nil {
		return true, fmt.Errorf("clear invalid pending authentication: %w", err)
	}
	ctx.Input.CruSession.SessionRelease(stdcontext.Background(), ctx.ResponseWriter)
	// Fail closed for this request even though the invalid or expired state has
	// been removed. A following authorization request may use auto sign-in.
	return true, nil
}

func fastAutoSignin(ctx *context.Context) (string, error) {
	request := object.AuthorizationRequest{
		ClientId:        ctx.Input.Query("client_id"),
		ResponseType:    ctx.Input.Query("response_type"),
		RedirectUri:     ctx.Input.Query("redirect_uri"),
		Scope:           ctx.Input.Query("scope"),
		State:           ctx.Input.Query("state"),
		Nonce:           ctx.Input.Query("nonce"),
		ChallengeMethod: ctx.Input.Query("code_challenge_method"),
		CodeChallenge:   ctx.Input.Query("code_challenge"),
		Resource:        ctx.Input.Query("resource"),
		Prompt:          ctx.Input.Query("prompt"),
	}
	if maxAgeValue := ctx.Input.Query("max_age"); maxAgeValue != "" {
		maxAge, err := strconv.ParseInt(maxAgeValue, 10, 64)
		if err != nil {
			return "", fmt.Errorf("max_age must be an integer")
		}
		request.MaxAge = &maxAge
	}
	if request.ClientId == "" || request.ResponseType != "code" || request.RedirectUri == "" {
		return "", nil
	}
	if err := request.Validate(); err != nil {
		return "", err
	}

	application, err := object.GetApplicationByClientId(request.ClientId)
	if err != nil {
		return "", err
	}
	if application == nil {
		return "", nil
	}
	if !application.IsRedirectUriValid(request.RedirectUri) {
		return "", fmt.Errorf("redirect_uri is not registered for the OAuth client")
	}
	if !object.IsScopeValid(request.Scope, application) {
		return "", fmt.Errorf("invalid OAuth scope")
	}
	prompts, err := request.PromptValues()
	if err != nil {
		return "", err
	}
	promptNone := slices.Contains(prompts, "none")
	requireInteraction := func(errorCode string) (string, error) {
		if promptNone {
			return oauthErrorRedirect(request, errorCode), nil
		}
		return "", nil
	}

	if !application.EnableAutoSignin {
		return requireInteraction("login_required")
	}

	userId := getSessionUser(ctx)
	if userId == "" {
		return requireInteraction("login_required")
	}
	pendingBlocks, pendingErr := pendingAuthenticationBlocksAutoSignin(ctx)
	if pendingErr != nil {
		return "", pendingErr
	}
	if pendingBlocks {
		return requireInteraction("login_required")
	}
	if mfaUser := ctx.Input.CruSession.Get(stdcontext.Background(), object.MfaSessionUserId); mfaUser != nil {
		if value, ok := mfaUser.(string); !ok || value != "" {
			return requireInteraction("login_required")
		}
	}

	if sessionDataValue := ctx.Input.CruSession.Get(stdcontext.Background(), "SessionData"); sessionDataValue != nil {
		serializedSessionData, ok := sessionDataValue.(string)
		if !ok {
			return requireInteraction("login_required")
		}
		var sessionData struct {
			ExpireTime int64
		}
		if err = util.JsonToStruct(serializedSessionData, &sessionData); err != nil ||
			(sessionData.ExpireTime != 0 && sessionData.ExpireTime < time.Now().Unix()) {
			return requireInteraction("login_required")
		}
	}

	authenticationContextValue := ctx.Input.CruSession.Get(stdcontext.Background(), object.CurrentAuthenticationContextSessionKey)
	if authenticationContextValue == nil {
		return requireInteraction("login_required")
	}
	serializedAuthenticationContext, ok := authenticationContextValue.(string)
	if !ok {
		return requireInteraction("login_required")
	}
	var authenticationContext object.AuthenticationContext
	if err = util.JsonToStruct(serializedAuthenticationContext, &authenticationContext); err != nil {
		return requireInteraction("login_required")
	}
	authenticationContext, err = object.PreserveAuthenticationContext(authenticationContext)
	if err != nil || authenticationContext.Subject != userId {
		return requireInteraction("login_required")
	}
	if request.RequiresFreshAuthentication(authenticationContext, time.Now().Unix()) {
		return requireInteraction("login_required")
	}
	if slices.Contains(prompts, "consent") {
		return "", nil
	}

	isAllowed, err := object.CheckLoginPermission(userId, application)
	if err != nil {
		return "", err
	}

	if !isAllowed {
		return requireInteraction("access_denied")
	}

	user, err := object.GetUser(userId)
	if err != nil {
		return "", err
	}
	if user == nil {
		return requireInteraction("login_required")
	}

	consentRequired, err := object.CheckConsentRequired(user, application, request.Scope)
	if err != nil {
		return "", err
	}

	if consentRequired {
		return requireInteraction("consent_required")
	}

	code, err := object.GetOAuthCodeWithAuthenticationContext(
		userId,
		request.ClientId,
		authenticationContext,
		request.ResponseType,
		request.RedirectUri,
		request.Scope,
		request.State,
		request.Nonce,
		request.CodeChallenge,
		request.Resource,
		ctx.Request.Host,
		getAcceptLanguage(ctx),
	)
	if err != nil {
		return "", err
	} else if code == nil {
		return "", errors.New("failed to create OAuth authorization code")
	} else if code.Message != "" {
		return "", errors.New(code.Message)
	} else if code.Code == "" {
		return "", errors.New("failed to create OAuth authorization code")
	}

	return oauthSuccessRedirect(request, code.Code)
}

func oauthSuccessRedirect(request object.AuthorizationRequest, code string) (string, error) {
	redirectUrl, err := url.Parse(request.RedirectUri)
	if err != nil {
		return "", err
	}
	query := redirectUrl.Query()
	query.Set("code", code)
	query.Set("state", request.State)
	redirectUrl.RawQuery = query.Encode()
	return redirectUrl.String(), nil
}

func oauthErrorRedirect(request object.AuthorizationRequest, errorCode string) string {
	redirectUrl, err := url.Parse(request.RedirectUri)
	if err != nil {
		return request.RedirectUri
	}
	query := redirectUrl.Query()
	query.Set("error", errorCode)
	if request.State != "" {
		query.Set("state", request.State)
	}
	redirectUrl.RawQuery = query.Encode()
	return redirectUrl.String()
}

func StaticFilter(ctx *context.Context) {
	urlPath := ctx.Request.URL.Path

	if urlPath == "/.well-known/acme-challenge/filename" {
		http.ServeContent(ctx.ResponseWriter, ctx.Request, "acme-challenge", time.Now(), strings.NewReader("content"))
	}

	if strings.HasPrefix(urlPath, "/api/") || strings.HasPrefix(urlPath, "/.well-known/") {
		return
	}
	if serveAuthCallbackHandlerScript(ctx) {
		return
	}
	if serveProviderHintRedirectScript(ctx) {
		return
	}
	if strings.HasPrefix(urlPath, "/cas") && (strings.HasSuffix(urlPath, "/serviceValidate") || strings.HasSuffix(urlPath, "/proxy") || strings.HasSuffix(urlPath, "/proxyValidate") || strings.HasSuffix(urlPath, "/validate") || strings.HasSuffix(urlPath, "/p3/serviceValidate") || strings.HasSuffix(urlPath, "/p3/proxyValidate") || strings.HasSuffix(urlPath, "/samlValidate")) {
		return
	}
	if strings.HasPrefix(urlPath, "/scim") {
		return
	}

	if urlPath == "/login/oauth/authorize" {
		redirectUrl, err := fastAutoSignin(ctx)
		if err != nil {
			responseError(ctx, err.Error())
			return
		}

		if redirectUrl != "" {
			http.Redirect(ctx.ResponseWriter, ctx.Request, redirectUrl, http.StatusFound)
			return
		}

		if serveProviderHintRedirectPage(ctx) {
			return
		}
	}

	if serveAuthCallbackPage(ctx) {
		return
	}

	webBuildFolder := getWebBuildFolder()
	path := webBuildFolder
	if urlPath == "/" {
		path += "/index.html"
	} else {
		path += urlPath
	}

	// Preventing synchronization problems from concurrency
	ctx.Input.CruSession = nil

	organizationThemeCookie, err := appendThemeCookie(ctx, urlPath)
	if err != nil {
		fmt.Println(err)
	}

	if strings.Contains(path, "/../") || !util.FileExist(path) {
		path = webBuildFolder + "/index.html"
	}
	if strings.HasSuffix(path, "/index.html") {
		err = util.AppendWebConfigCookie(ctx)
		if err != nil {
			logs.Error("AppendWebConfigCookie failed in StaticFilter, error: %s", err)
		}
	}
	if !util.FileExist(path) {
		dir, err := os.Getwd()
		if err != nil {
			panic(err)
		}
		dir = strings.ReplaceAll(dir, "\\", "/")
		ctx.ResponseWriter.WriteHeader(http.StatusNotFound)
		errorText := fmt.Sprintf("The Casdoor frontend HTML file: \"index.html\" was not found, it should be placed at: \"%s/web/build/index.html\". For more information, see: https://casdoor.org/docs/basic/server-installation/#frontend-1", dir)
		http.ServeContent(ctx.ResponseWriter, ctx.Request, "Casdoor frontend has encountered error...", time.Now(), strings.NewReader(errorText))
		return
	}

	if oldStaticBaseUrl == newStaticBaseUrl {
		makeGzipResponse(ctx.ResponseWriter, ctx.Request, path, organizationThemeCookie)
	} else {
		serveFileWithReplace(ctx.ResponseWriter, ctx.Request, path, organizationThemeCookie)
	}
}

func serveFileWithReplace(w http.ResponseWriter, r *http.Request, name string, organizationThemeCookie *OrganizationThemeCookie) {
	f, err := os.Open(filepath.Clean(name))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	d, err := f.Stat()
	if err != nil {
		panic(err)
	}

	oldContent := util.ReadStringFromPath(name)
	newContent := oldContent
	if organizationThemeCookie != nil {
		newContent = strings.ReplaceAll(newContent, "https://cdn.casbin.org/img/favicon.png", organizationThemeCookie.Favicon)
		newContent = strings.ReplaceAll(newContent, "<title>Casdoor</title>", fmt.Sprintf("<title>%s</title>", organizationThemeCookie.DisplayName))
	}

	newContent = strings.ReplaceAll(newContent, oldStaticBaseUrl, newStaticBaseUrl)

	http.ServeContent(w, r, d.Name(), d.ModTime(), strings.NewReader(newContent))
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func makeGzipResponse(w http.ResponseWriter, r *http.Request, path string, organizationThemeCookie *OrganizationThemeCookie) {
	if !enableGzip || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		serveFileWithReplace(w, r, path, organizationThemeCookie)
		return
	}
	w.Header().Set("Content-Encoding", "gzip")
	gz := gzip.NewWriter(w)
	defer gz.Close()
	gzw := gzipResponseWriter{Writer: gz, ResponseWriter: w}
	serveFileWithReplace(gzw, r, path, organizationThemeCookie)
}
