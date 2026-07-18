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

package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/session"
)

func TestWerkblickSessionConfigurationEnforcesHostOnlyLaxCookie(t *testing.T) {
	sessionConfig := web.SessionConfig{
		SessionAutoSetCookie:         false,
		SessionDisableHTTPOnly:       true,
		SessionEnableSidInHTTPHeader: true,
		SessionEnableSidInURLQuery:   true,
		SessionName:                  "casdoor_session_id",
		SessionDomain:                ".demo.werkblick.tech",
		SessionCookieSameSite:        http.SameSiteNoneMode,
		SessionProvider:              "memory",
		SessionProviderConfig:        "legacy",
		SessionCookieLifeTime:        1,
		SessionGCMaxLifetime:         1,
	}

	applyWerkblickSessionConfiguration(&sessionConfig, "", 7200)

	if !sessionConfig.SessionOn || !sessionConfig.SessionAutoSetCookie || sessionConfig.SessionDisableHTTPOnly {
		t.Fatalf("session cookie safety flags were not enforced: %#v", sessionConfig)
	}
	if sessionConfig.SessionEnableSidInHTTPHeader || sessionConfig.SessionEnableSidInURLQuery {
		t.Fatalf("alternate SID transports remain enabled: %#v", sessionConfig)
	}
	if werkblickSessionName != "__Host-casdoor_session_id" {
		t.Fatalf("Werkblick session constant = %q", werkblickSessionName)
	}
	if sessionConfig.SessionName != werkblickSessionName {
		t.Fatalf("session name = %q, want unique __Host- cookie", sessionConfig.SessionName)
	}
	if sessionConfig.SessionDomain != "" {
		t.Fatalf("session domain = %q, want host-only cookie", sessionConfig.SessionDomain)
	}
	if sessionConfig.SessionCookieSameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", sessionConfig.SessionCookieSameSite)
	}
	if sessionConfig.SessionProvider != "file" || sessionConfig.SessionProviderConfig != "./tmp" {
		t.Fatalf("file session provider = (%q, %q)", sessionConfig.SessionProvider, sessionConfig.SessionProviderConfig)
	}
	if sessionConfig.SessionCookieLifeTime != 7200 || sessionConfig.SessionGCMaxLifetime != 7200 {
		t.Fatalf("session lifetime = (%d, %d), want 7200", sessionConfig.SessionCookieLifeTime, sessionConfig.SessionGCMaxLifetime)
	}
}

func TestWerkblickSessionConfigurationUsesRedisAndDefaultLifetime(t *testing.T) {
	sessionConfig := web.SessionConfig{}
	applyWerkblickSessionConfiguration(&sessionConfig, "redis:6379", 0)

	if sessionConfig.SessionProvider != "redis" || sessionConfig.SessionProviderConfig != "redis:6379" {
		t.Fatalf("Redis session provider = (%q, %q)", sessionConfig.SessionProvider, sessionConfig.SessionProviderConfig)
	}
	if sessionConfig.SessionCookieLifeTime != defaultSessionLifetime || sessionConfig.SessionGCMaxLifetime != defaultSessionLifetime {
		t.Fatalf("default session lifetime = (%d, %d), want %d", sessionConfig.SessionCookieLifeTime, sessionConfig.SessionGCMaxLifetime, defaultSessionLifetime)
	}
}

func TestConfigureSessionClearsLegacyJsonOverride(t *testing.T) {
	originalSessionConfig := web.BConfig.WebConfig.Session
	originalJsonOverride, _ := web.AppConfig.String("sessionConfig")
	originalRuntimeProfile := werkblickRuntimeProfile
	t.Cleanup(func() {
		web.BConfig.WebConfig.Session = originalSessionConfig
		werkblickRuntimeProfile = originalRuntimeProfile
		if err := web.AppConfig.Set("sessionConfig", originalJsonOverride); err != nil {
			t.Errorf("restore sessionConfig: %v", err)
		}
	})

	if err := web.AppConfig.Set("sessionConfig", `{"cookieName":"casdoor_session_id","domain":".werkblick.tech"}`); err != nil {
		t.Fatal(err)
	}
	werkblickRuntimeProfile = werkblickHardenedRuntimeProfile
	t.Setenv("redisEndpoint", "redis:6379")
	t.Setenv("sessionCookieLifeTime", "600")

	configureSession()

	jsonOverride, err := web.AppConfig.String("sessionConfig")
	if err != nil {
		t.Fatal(err)
	}
	if jsonOverride != "" {
		t.Fatalf("legacy sessionConfig override remains active: %q", jsonOverride)
	}
	sessionConfig := web.BConfig.WebConfig.Session
	if sessionConfig.SessionName != werkblickSessionName || sessionConfig.SessionDomain != "" || sessionConfig.SessionCookieSameSite != http.SameSiteLaxMode {
		t.Fatalf("hardened session cookie contract was not applied: %#v", sessionConfig)
	}
	if sessionConfig.SessionProvider != "redis" || sessionConfig.SessionProviderConfig != "redis:6379" {
		t.Fatalf("configured Redis session provider = (%q, %q)", sessionConfig.SessionProvider, sessionConfig.SessionProviderConfig)
	}
	if sessionConfig.SessionCookieLifeTime != 600 || sessionConfig.SessionGCMaxLifetime != 600 {
		t.Fatalf("configured session lifetime = (%d, %d)", sessionConfig.SessionCookieLifeTime, sessionConfig.SessionGCMaxLifetime)
	}
}

func TestStandardRuntimeKeepsDevelopmentCookieContract(t *testing.T) {
	originalSessionConfig := web.BConfig.WebConfig.Session
	originalJsonOverride, _ := web.AppConfig.String("sessionConfig")
	originalRuntimeProfile := werkblickRuntimeProfile
	t.Cleanup(func() {
		web.BConfig.WebConfig.Session = originalSessionConfig
		werkblickRuntimeProfile = originalRuntimeProfile
		if err := web.AppConfig.Set("sessionConfig", originalJsonOverride); err != nil {
			t.Errorf("restore sessionConfig: %v", err)
		}
	})

	if err := web.AppConfig.Set("sessionConfig", `{"cookieName":"unsafe","domain":".werkblick.tech","enableSidInHttpHeader":true}`); err != nil {
		t.Fatal(err)
	}
	web.BConfig.WebConfig.Session = web.SessionConfig{
		SessionAutoSetCookie:         false,
		SessionDisableHTTPOnly:       true,
		SessionEnableSidInHTTPHeader: true,
		SessionEnableSidInURLQuery:   true,
		SessionDomain:                ".werkblick.tech",
		SessionCookieSameSite:        http.SameSiteNoneMode,
	}
	werkblickRuntimeProfile = ""
	t.Setenv("redisEndpoint", "")
	t.Setenv("sessionCookieLifeTime", "600")

	configureSession()

	jsonOverride, err := web.AppConfig.String("sessionConfig")
	if err != nil {
		t.Fatal(err)
	}
	if jsonOverride != "" {
		t.Fatalf("legacy sessionConfig override remains active: %q", jsonOverride)
	}
	sessionConfig := web.BConfig.WebConfig.Session
	if sessionConfig.SessionName != standardSessionName {
		t.Fatalf("standard session name = %q, want %q", sessionConfig.SessionName, standardSessionName)
	}
	if !sessionConfig.SessionOn || !sessionConfig.SessionAutoSetCookie || sessionConfig.SessionDisableHTTPOnly {
		t.Fatalf("standard session safety flags were not enforced: %#v", sessionConfig)
	}
	if sessionConfig.SessionEnableSidInHTTPHeader || sessionConfig.SessionEnableSidInURLQuery {
		t.Fatalf("alternate SID transports remain enabled: %#v", sessionConfig)
	}
	if sessionConfig.SessionDomain != "" || sessionConfig.SessionCookieSameSite != http.SameSiteLaxMode {
		t.Fatalf("standard host-only SameSite contract was not applied: %#v", sessionConfig)
	}
	if sessionConfig.SessionProvider != "file" || sessionConfig.SessionProviderConfig != "./tmp" {
		t.Fatalf("standard session provider = (%q, %q)", sessionConfig.SessionProvider, sessionConfig.SessionProviderConfig)
	}
	if sessionConfig.SessionCookieLifeTime != 600 || sessionConfig.SessionGCMaxLifetime != 600 {
		t.Fatalf("standard session lifetime = (%d, %d)", sessionConfig.SessionCookieLifeTime, sessionConfig.SessionGCMaxLifetime)
	}
}

func TestRuntimeProfileRequiresExactCompiledMarker(t *testing.T) {
	originalRuntimeProfile := werkblickRuntimeProfile
	t.Cleanup(func() { werkblickRuntimeProfile = originalRuntimeProfile })

	werkblickRuntimeProfile = ""
	if got := resolvedRuntimeProfile(); got != "standard" {
		t.Fatalf("default runtime profile = %q, want standard", got)
	}
	werkblickRuntimeProfile = werkblickHardenedRuntimeProfile
	if got := resolvedRuntimeProfile(); got != werkblickHardenedRuntimeProfile {
		t.Fatalf("hardened runtime profile = %q", got)
	}

	werkblickRuntimeProfile = "unexpected"
	defer func() {
		if recover() == nil {
			t.Fatal("unknown compiled runtime profile did not fail closed")
		}
	}()
	resolvedRuntimeProfile()
}

func TestWerkblickSessionCookieHeaderRequiresProxySecureFlag(t *testing.T) {
	sessionConfig := web.SessionConfig{}
	applyWerkblickSessionConfiguration(&sessionConfig, "", 600)
	manager, err := session.NewManager("memory", &session.ManagerConfig{
		CookieName:      sessionConfig.SessionName,
		EnableSetCookie: sessionConfig.SessionAutoSetCookie,
		DisableHTTPOnly: sessionConfig.SessionDisableHTTPOnly,
		Domain:          sessionConfig.SessionDomain,
		CookieSameSite:  sessionConfig.SessionCookieSameSite,
		CookieLifeTime:  sessionConfig.SessionCookieLifeTime,
		Gclifetime:      sessionConfig.SessionGCMaxLifetime,
		Maxlifetime:     sessionConfig.SessionGCMaxLifetime,
		SessionIDLength: 32,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://casdoor:8000/api/get-account", nil)
	recorder := httptest.NewRecorder()
	if _, err = manager.SessionStart(recorder, request); err != nil {
		t.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("session cookies = %#v, want exactly one", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != werkblickSessionName || cookie.Path != "/" || cookie.Domain != "" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("upstream session cookie contract = %#v", cookie)
	}
	if cookie.Secure {
		t.Fatal("plain-HTTP upstream unexpectedly set Secure; the test no longer proves the mandatory proxy rule")
	}
}

func TestSchemaMigrationOnlyStopsAfterCreateTables(t *testing.T) {
	events := []string{}
	hooks := startupHooks{
		configureSession: func() { events = append(events, "configure-session") },
		initAPI:          func() { events = append(events, "init-api") },
		initFlag:         func() { events = append(events, "init-flag") },
		initAdapter:      func() { events = append(events, "init-adapter") },
		createTables:     func() { events = append(events, "create-tables") },
		initDb:           func() { events = append(events, "init-db") },
		initFromFile:     func() { events = append(events, "init-from-file") },
		startNormalBoot:  func() { events = append(events, "normal-boot") },
	}

	mode, err := runStartup("true", "", hooks)
	if err != nil {
		t.Fatal(err)
	}
	if mode != startupModeSchemaOnly {
		t.Fatalf("startup mode = %q, want schema-only", mode)
	}

	want := []string{"init-api", "init-flag", "init-adapter", "create-tables"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("startup events = %v, want %v", events, want)
	}
}

func TestSpecialStartupFlagsAcceptOnlyExplicitBooleanValues(t *testing.T) {
	for _, value := range []string{"", "false"} {
		t.Run(value, func(t *testing.T) {
			normalBootCalls := 0
			hooks := startupHooks{
				configureSession: func() {},
				initAPI:          func() {},
				initFlag:         func() {},
				initAdapter:      func() {},
				createTables:     func() {},
				initDb:           func() {},
				initFromFile:     func() {},
				startNormalBoot:  func() { normalBootCalls++ },
			}

			mode, err := runStartup(value, value, hooks)
			if err != nil {
				t.Fatal(err)
			}
			if mode != startupModeNormal {
				t.Fatalf("value %q unexpectedly enabled mode %q", value, mode)
			}
			if normalBootCalls != 1 {
				t.Fatalf("normal boot calls = %d, want 1", normalBootCalls)
			}
		})
	}
}

func TestInvalidSpecialStartupFlagsFailBeforeInitialization(t *testing.T) {
	for _, test := range []struct {
		name      string
		migration string
		bootstrap string
	}{
		{name: "uppercase migration", migration: "TRUE"},
		{name: "numeric migration", migration: "1"},
		{name: "whitespace migration", migration: " true "},
		{name: "newline migration", migration: "true\n"},
		{name: "uppercase bootstrap", bootstrap: "FALSE"},
		{name: "numeric bootstrap", bootstrap: "0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			hooks := startupHooks{
				configureSession: func() { events = append(events, "configure-session") },
				initAPI:          func() { events = append(events, "init-api") },
				initFlag:         func() { events = append(events, "init-flag") },
				initAdapter:      func() { events = append(events, "init-adapter") },
				createTables:     func() { events = append(events, "create-tables") },
				initDb:           func() { events = append(events, "init-db") },
				initFromFile:     func() { events = append(events, "init-from-file") },
				startNormalBoot:  func() { events = append(events, "normal-boot") },
			}

			mode, err := runStartup(test.migration, test.bootstrap, hooks)
			if err == nil {
				t.Fatal("invalid startup flag was accepted")
			}
			if mode != "" {
				t.Fatalf("startup mode = %q, want empty", mode)
			}
			if len(events) != 0 {
				t.Fatalf("startup hooks ran before flag validation: %v", events)
			}
		})
	}
}

func TestBootstrapDataOnlyHasIsolatedCallOrder(t *testing.T) {
	events := []string{}
	hooks := startupHooks{
		configureSession: func() { events = append(events, "configure-session") },
		initAPI:          func() { events = append(events, "init-api") },
		initFlag:         func() { events = append(events, "init-flag") },
		initAdapter:      func() { events = append(events, "init-adapter") },
		createTables:     func() { events = append(events, "create-tables") },
		initDb:           func() { events = append(events, "init-db") },
		initFromFile:     func() { events = append(events, "init-from-file") },
		startNormalBoot:  func() { events = append(events, "normal-boot") },
	}

	mode, err := runStartup("", "true", hooks)
	if err != nil {
		t.Fatal(err)
	}
	if mode != startupModeBootstrapOnly {
		t.Fatalf("startup mode = %q, want bootstrap-data-only", mode)
	}

	want := []string{"init-api", "init-flag", "init-adapter", "create-tables", "init-from-file", "init-db"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("startup events = %v, want %v", events, want)
	}
}

func TestNormalStartupConfiguresSessionBeforeRoutes(t *testing.T) {
	events := []string{}
	hooks := startupHooks{
		configureSession: func() { events = append(events, "configure-session") },
		initAPI:          func() { events = append(events, "init-api") },
		initFlag:         func() { events = append(events, "init-flag") },
		initAdapter:      func() { events = append(events, "init-adapter") },
		createTables:     func() { events = append(events, "create-tables") },
		initDb:           func() { events = append(events, "init-db") },
		initFromFile:     func() { events = append(events, "init-from-file") },
		startNormalBoot:  func() { events = append(events, "normal-boot") },
	}

	mode, err := runStartup("", "", hooks)
	if err != nil {
		t.Fatal(err)
	}
	if mode != startupModeNormal {
		t.Fatalf("startup mode = %q, want normal", mode)
	}

	want := []string{"configure-session", "init-api", "init-flag", "init-adapter", "create-tables", "normal-boot"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("startup events = %v, want %v", events, want)
	}
}

func TestSpecialStartupModesAreMutuallyExclusive(t *testing.T) {
	events := []string{}
	hooks := startupHooks{
		configureSession: func() { events = append(events, "configure-session") },
		initAPI:          func() { events = append(events, "init-api") },
		initFlag:         func() { events = append(events, "init-flag") },
		initAdapter:      func() { events = append(events, "init-adapter") },
		createTables:     func() { events = append(events, "create-tables") },
		initDb:           func() { events = append(events, "init-db") },
		initFromFile:     func() { events = append(events, "init-from-file") },
		startNormalBoot:  func() { events = append(events, "normal-boot") },
	}

	mode, err := runStartup("true", "true", hooks)
	if err == nil {
		t.Fatal("both special startup modes were accepted")
	}
	if mode != "" {
		t.Fatalf("startup mode = %q, want empty on configuration error", mode)
	}
	if len(events) != 0 {
		t.Fatalf("startup hooks ran before mutual-exclusion failure: %v", events)
	}
}
