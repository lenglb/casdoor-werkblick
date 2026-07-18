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

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	_ "github.com/beego/beego/v2/server/web/session/redis"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/ldap"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/casdoor/casdoor/radius"
	"github.com/casdoor/casdoor/routers"
	"github.com/casdoor/casdoor/service"
	"github.com/casdoor/casdoor/util"
)

const (
	schemaMigrationOnlyEnv          = "WERKBLICK_SCHEMA_MIGRATION_ONLY"
	bootstrapDataOnlyEnv            = "WERKBLICK_BOOTSTRAP_DATA_ONLY"
	runtimeProfileOnlyEnv           = "WERKBLICK_RUNTIME_PROFILE_ONLY"
	werkblickHardenedRuntimeProfile = "werkblick-hardened-v1"
	werkblickSessionName            = "__Host-casdoor_session_id"
	standardSessionName             = "casdoor_session_id"
	defaultSessionLifetime          = 3600 * 24 * 30
)

// werkblickRuntimeProfile is empty in upstream-compatible development builds.
// Dockerfile.werkblick binds the hardened profile at link time, and CI verifies
// the finished image before release publication. Runtime configuration cannot
// change or disable the compiled profile.
var werkblickRuntimeProfile string

type startupMode string

const (
	startupModeNormal        startupMode = "normal"
	startupModeSchemaOnly    startupMode = "schema-only"
	startupModeBootstrapOnly startupMode = "bootstrap-data-only"
)

type startupHooks struct {
	configureSession func()
	initAPI          func()
	initFlag         func()
	initAdapter      func()
	createTables     func()
	initDb           func()
	initFromFile     func()
	startNormalBoot  func()
}

func parseStartupBoolean(name string, value string) (bool, error) {
	switch value {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be empty, false, or true; got %q", name, value)
	}
}

// runStartup validates both one-shot controls before any initialization hook.
// Typos fail closed instead of starting a listener before the intended
// migration or bootstrap quarantine has run.
func runStartup(migrationOnlyValue string, bootstrapOnlyValue string, hooks startupHooks) (startupMode, error) {
	migrationOnly, err := parseStartupBoolean(schemaMigrationOnlyEnv, migrationOnlyValue)
	if err != nil {
		return "", err
	}
	bootstrapOnly, err := parseStartupBoolean(bootstrapDataOnlyEnv, bootstrapOnlyValue)
	if err != nil {
		return "", err
	}
	if migrationOnly && bootstrapOnly {
		return "", fmt.Errorf("%s and %s are mutually exclusive", schemaMigrationOnlyEnv, bootstrapDataOnlyEnv)
	}

	if !migrationOnly && !bootstrapOnly {
		// Beego snapshots SessionOn into each route as it is registered.
		// Configure sessions before InitAPI so normal routes receive a store.
		hooks.configureSession()
	}
	hooks.initAPI()
	hooks.initFlag()
	hooks.initAdapter()
	hooks.createTables()

	if migrationOnly {
		return startupModeSchemaOnly, nil
	}
	if bootstrapOnly {
		hooks.initFromFile()
		hooks.initDb()
		return startupModeBootstrapOnly, nil
	}

	hooks.startNormalBoot()
	return startupModeNormal, nil
}

func main() {
	if os.Getenv(runtimeProfileOnlyEnv) == "true" {
		fmt.Println(resolvedRuntimeProfile())
		return
	}

	mode, err := runStartup(os.Getenv(schemaMigrationOnlyEnv), os.Getenv(bootstrapDataOnlyEnv), startupHooks{
		configureSession: configureSession,
		initAPI:          routers.InitAPI,
		initFlag:         object.InitFlag,
		initAdapter:      object.InitAdapter,
		createTables:     object.CreateTables,
		initDb:           object.InitDb,
		initFromFile:     object.InitFromFileRequired,
		startNormalBoot:  startNormalBoot,
	})
	if err != nil {
		log.Fatal(err)
	}
	if mode == startupModeSchemaOnly {
		log.Printf("schema migration completed; %s=true, exiting before service initialization", schemaMigrationOnlyEnv)
	} else if mode == startupModeBootstrapOnly {
		log.Printf("bootstrap data import completed; %s=true, exiting before service initialization", bootstrapDataOnlyEnv)
	}
}

func resolvedRuntimeProfile() string {
	switch werkblickRuntimeProfile {
	case "":
		return "standard"
	case werkblickHardenedRuntimeProfile:
		return werkblickHardenedRuntimeProfile
	default:
		panic(fmt.Sprintf("unsupported compiled runtime profile %q", werkblickRuntimeProfile))
	}
}

func configureSession() {
	sessionCookieLifeTime := defaultSessionLifetime
	if val, err := conf.GetConfigInt64("sessionCookieLifeTime"); err == nil && val > 0 {
		sessionCookieLifeTime = int(val)
	}
	redisEndpoint := conf.GetConfigString("redisEndpoint")

	// Beego's JSON sessionConfig bypasses every typed field below. Both the
	// upstream-compatible development profile and the hardened Werkblick image
	// own their complete cookie contract, so mounted legacy JSON must not be
	// allowed to restore a parent-domain cookie or alternate SID transports.
	if err := web.AppConfig.Set("sessionConfig", ""); err != nil {
		panic(fmt.Sprintf("disable legacy sessionConfig override: %v", err))
	}

	if resolvedRuntimeProfile() == "standard" {
		applyStandardSessionConfiguration(
			&web.BConfig.WebConfig.Session,
			redisEndpoint,
			sessionCookieLifeTime,
		)
		return
	}

	applyWerkblickSessionConfiguration(
		&web.BConfig.WebConfig.Session,
		redisEndpoint,
		sessionCookieLifeTime,
	)
}

func applyStandardSessionConfiguration(sessionConfig *web.SessionConfig, redisEndpoint string, sessionCookieLifeTime int) {
	if sessionCookieLifeTime <= 0 {
		sessionCookieLifeTime = defaultSessionLifetime
	}

	sessionConfig.SessionOn = true
	sessionConfig.SessionAutoSetCookie = true
	sessionConfig.SessionDisableHTTPOnly = false
	sessionConfig.SessionEnableSidInHTTPHeader = false
	sessionConfig.SessionEnableSidInURLQuery = false
	sessionConfig.SessionName = standardSessionName
	sessionConfig.SessionDomain = ""
	sessionConfig.SessionCookieSameSite = http.SameSiteLaxMode
	if redisEndpoint == "" {
		sessionConfig.SessionProvider = "file"
		sessionConfig.SessionProviderConfig = "./tmp"
	} else {
		sessionConfig.SessionProvider = "redis"
		sessionConfig.SessionProviderConfig = redisEndpoint
	}
	sessionConfig.SessionCookieLifeTime = sessionCookieLifeTime
	sessionConfig.SessionGCMaxLifetime = int64(sessionCookieLifeTime)
}

func applyWerkblickSessionConfiguration(sessionConfig *web.SessionConfig, redisEndpoint string, sessionCookieLifeTime int) {
	if sessionCookieLifeTime <= 0 {
		sessionCookieLifeTime = defaultSessionLifetime
	}

	sessionConfig.SessionOn = true
	sessionConfig.SessionAutoSetCookie = true
	sessionConfig.SessionDisableHTTPOnly = false
	sessionConfig.SessionEnableSidInHTTPHeader = false
	sessionConfig.SessionEnableSidInURLQuery = false
	sessionConfig.SessionName = werkblickSessionName
	sessionConfig.SessionDomain = ""
	sessionConfig.SessionCookieSameSite = http.SameSiteLaxMode
	if redisEndpoint == "" {
		sessionConfig.SessionProvider = "file"
		sessionConfig.SessionProviderConfig = "./tmp"
	} else {
		sessionConfig.SessionProvider = "redis"
		sessionConfig.SessionProviderConfig = redisEndpoint
	}
	sessionConfig.SessionCookieLifeTime = sessionCookieLifeTime
	sessionConfig.SessionGCMaxLifetime = int64(sessionCookieLifeTime)
	// Beego derives Secure from the connection that reaches it and therefore
	// omits the flag behind TLS termination. The Nginx consumer must add Secure
	// to this exact cookie before it reaches the browser; see the release guide.
}

func startNormalBoot() {
	object.InitDb()

	// Handle export command
	if object.ShouldExportData() {
		exportPath := object.GetExportFilePath()
		err := object.DumpToFile(exportPath)
		if err != nil {
			panic(fmt.Sprintf("Error exporting data to %s: %v", exportPath, err))
		}
		fmt.Printf("Data exported successfully to %s\n", exportPath)
		return
	}

	object.InitDefaultStorageProvider()
	object.InitLogProviders()
	object.InitLdapAutoSynchronizer()
	proxy.InitHttpClient()
	authz.InitApi()
	object.InitUserManager()
	object.InitFromFile()
	object.InitCleanupTokens()
	object.InitCleanupDeviceAuthMap()

	object.InitSiteMap()
	if len(object.SiteMap) != 0 {
		object.InitRuleMap()
		object.StartMonitorSitesLoop()
	}

	util.SafeGoroutine(func() { object.RunSyncUsersJob() })
	util.SafeGoroutine(func() { controllers.InitCLIDownloader() })

	// web.DelStaticPath("/static")
	// web.SetStaticPath("/static", "web/build/static")

	web.BConfig.WebConfig.DirectoryIndex = true
	if web.BConfig.RunMode == "dev" {
		web.SetStaticPath("/swagger", "swagger")
	}
	web.SetStaticPath("/files", "files")
	// https://studygolang.com/articles/2303
	web.InsertFilter("*", web.BeforeStatic, routers.RequestBodyFilter)
	web.InsertFilter("*", web.BeforeStatic, routers.ContentTypeFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.StaticFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.AutoSigninFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.CorsFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.TimeoutFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.ApiFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.PrometheusFilter)
	web.InsertFilter("*", web.BeforeRouter, routers.RecordMessage)
	web.InsertFilter("*", web.BeforeRouter, routers.FieldValidationFilter)
	web.InsertFilter("*", web.AfterExec, routers.AfterRecordMessage, web.WithReturnOnOutput(false))

	var logAdapter string
	logConfigMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(conf.GetConfigString("logConfig")), &logConfigMap)
	if err != nil {
		panic(err)
	}
	_, ok := logConfigMap["adapter"]
	if !ok {
		logAdapter = "file"
	} else {
		logAdapter = logConfigMap["adapter"].(string)
	}
	if logAdapter == "console" {
		logs.Reset()
	}
	err = logs.SetLogger(logAdapter, conf.GetConfigString("logConfig"))
	if err != nil {
		panic(err)
	}

	port := web.AppConfig.DefaultInt("httpport", 8000)
	// logs.SetLevel(logs.LevelInformational)
	logs.SetLogFuncCall(false)

	err = util.StopOldInstance(port)
	if err != nil {
		panic(err)
	}

	go ldap.StartLdapServer()
	go radius.StartRadiusServer()
	go object.ClearThroughputPerSecond()

	// Start webhook delivery worker
	object.StartWebhookDeliveryWorker()

	if len(object.SiteMap) != 0 {
		service.Start()
	}

	web.Run(fmt.Sprintf(":%v", port))
}
