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
	"reflect"
	"testing"
)

func TestSchemaMigrationOnlyStopsAfterCreateTables(t *testing.T) {
	events := []string{}
	hooks := startupHooks{
		initAPI:         func() { events = append(events, "init-api") },
		initFlag:        func() { events = append(events, "init-flag") },
		initAdapter:     func() { events = append(events, "init-adapter") },
		createTables:    func() { events = append(events, "create-tables") },
		initDb:          func() { events = append(events, "init-db") },
		initFromFile:    func() { events = append(events, "init-from-file") },
		startNormalBoot: func() { events = append(events, "normal-boot") },
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

func TestSchemaMigrationOnlyRequiresExactTrueLiteral(t *testing.T) {
	for _, value := range []string{"", "false", "TRUE", "1", " true ", "true\n"} {
		t.Run(value, func(t *testing.T) {
			normalBootCalls := 0
			hooks := startupHooks{
				initAPI:         func() {},
				initFlag:        func() {},
				initAdapter:     func() {},
				createTables:    func() {},
				initDb:          func() {},
				initFromFile:    func() {},
				startNormalBoot: func() { normalBootCalls++ },
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

func TestBootstrapDataOnlyHasIsolatedCallOrder(t *testing.T) {
	events := []string{}
	hooks := startupHooks{
		initAPI:         func() { events = append(events, "init-api") },
		initFlag:        func() { events = append(events, "init-flag") },
		initAdapter:     func() { events = append(events, "init-adapter") },
		createTables:    func() { events = append(events, "create-tables") },
		initDb:          func() { events = append(events, "init-db") },
		initFromFile:    func() { events = append(events, "init-from-file") },
		startNormalBoot: func() { events = append(events, "normal-boot") },
	}

	mode, err := runStartup("", "true", hooks)
	if err != nil {
		t.Fatal(err)
	}
	if mode != startupModeBootstrapOnly {
		t.Fatalf("startup mode = %q, want bootstrap-data-only", mode)
	}

	want := []string{"init-api", "init-flag", "init-adapter", "create-tables", "init-db", "init-from-file"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("startup events = %v, want %v", events, want)
	}
}

func TestSpecialStartupModesAreMutuallyExclusive(t *testing.T) {
	events := []string{}
	hooks := startupHooks{
		initAPI:         func() { events = append(events, "init-api") },
		initFlag:        func() { events = append(events, "init-flag") },
		initAdapter:     func() { events = append(events, "init-adapter") },
		createTables:    func() { events = append(events, "create-tables") },
		initDb:          func() { events = append(events, "init-db") },
		initFromFile:    func() { events = append(events, "init-from-file") },
		startNormalBoot: func() { events = append(events, "normal-boot") },
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
