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

import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import {
  newApplicationGrantTypes,
  normalizeApplicationGrantTypes,
  normalizeApplicationScopes,
} from "./ApplicationSecurityDefaults.mjs";

test("new applications start with an explicit empty OAuth grant allowlist", () => {
  const grants = newApplicationGrantTypes();
  assert.deepEqual(grants, []);
  for (const unsafeDefault of ["authorization_code", "password", "client_credentials", "token", "id_token", "refresh_token"]) {
    assert.equal(grants.includes(unsafeDefault), false);
  }
});

test("loading an application never promotes an empty grant list", () => {
  assert.deepEqual(normalizeApplicationGrantTypes(undefined), []);
  assert.deepEqual(normalizeApplicationGrantTypes(null), []);
  assert.deepEqual(normalizeApplicationGrantTypes([]), []);
  assert.deepEqual(normalizeApplicationGrantTypes(["authorization_code"]), ["authorization_code"]);
});

test("missing scope arrays become editable empty allowlists", () => {
  assert.deepEqual(normalizeApplicationScopes(undefined), []);
  assert.deepEqual(normalizeApplicationScopes(null), []);
  assert.deepEqual(normalizeApplicationScopes([{name: "openid"}]), [{name: "openid"}]);
});

test("the OAuth scope editor is not restricted to Agent applications", () => {
  const source = readFileSync(new URL("./ApplicationEditPage.js", import.meta.url), "utf8");
  assert.match(source, /<ScopeTable/);
  assert.doesNotMatch(source, /category === "Agent"[\s\S]{0,500}<ScopeTable/);
});
