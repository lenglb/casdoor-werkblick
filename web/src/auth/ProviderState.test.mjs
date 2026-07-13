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
import vm from "node:vm";
import {createProviderState, readProviderState} from "./ProviderState.mjs";

const nonce = "a".repeat(64);

function newStorage() {
  const values = new Map();
  return {
    getItem: (key) => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, value),
  };
}

test("regular provider state carries the server nonce and round-trips callback data", () => {
  const storage = newStorage();
  const state = createProviderState(nonce, "app", "github", "signup", false, {
    search: "?client_id=client&state=caller-state",
    pathname: "/login/oauth/authorize",
  }, storage);

  assert.match(state, new RegExp(`^${nonce}\\.`));
  const inner = new URLSearchParams(readProviderState(state, storage));
  assert.equal(inner.get("application"), "app");
  assert.equal(inner.get("provider"), "github");
  assert.equal(inner.get("method"), "signup");
  assert.equal(inner.get("state"), "caller-state");
});

test("short provider state is opaque and bound to the same browser session", () => {
  const storage = newStorage();
  const state = createProviderState(nonce, "app", "twitter", "link", true, {
    search: "",
    pathname: "/users/me",
  }, storage);

  assert.equal(state, nonce);
  const inner = new URLSearchParams(readProviderState(state, storage));
  assert.equal(inner.get("provider"), "twitter");
  assert.equal(inner.get("method"), "link");
  assert.equal(inner.get("from"), "/users/me");
  assert.throws(() => readProviderState(state, newStorage()), /not available/);
});

test("predictable legacy and malformed states are rejected", () => {
  const storage = newStorage();
  assert.throws(() => createProviderState("app-built-in", "app", "github", "signup", false, {search: "", pathname: "/"}, storage), /server-issued/);
  assert.throws(() => readProviderState("app-built-in", storage), /malformed/);
  assert.throws(() => readProviderState(`${nonce}.`, storage), /payload is missing/);
});

test("both callback implementations submit the provider-returned state", () => {
  const reactCallback = readFileSync(new URL("./AuthCallback.js", import.meta.url), "utf8");
  const lightweightCallback = readFileSync(new URL("../../public/AuthCallbackHandler.js", import.meta.url), "utf8");
  const providerHintRedirect = readFileSync(new URL("../../public/ProviderHintRedirect.js", import.meta.url), "utf8");
  const provider = readFileSync(new URL("./Provider.js", import.meta.url), "utf8");

  assert.match(reactCallback, /state:\s*returnedState/);
  assert.doesNotMatch(reactCallback, /state:\s*applicationName/);
  assert.match(lightweightCallback, /state:\s*params\.get\("state"\)/);
  assert.doesNotMatch(lightweightCallback, /state:\s*applicationName/);
  assert.match(provider, /application\.providerStates\?\.\[`\$\{provider\.name\}:\$\{normalizedMethod\}`\]/);
  assert.match(providerHintRedirect, /application\.providerStates\s*&&\s*application\.providerStates\[provider\.name\s*\+\s*":"\s*\+\s*normalizedMethod\]/);
  assert.doesNotMatch(providerHintRedirect, /var state = providerName/);
});

test("lightweight callback preserves and safely serializes the bound OAuth request", () => {
  const source = readFileSync(new URL("../../public/AuthCallbackHandler.js", import.meta.url), "utf8");
  const instrumented = source.replace(
    "window.CasdoorAuthCallback = {",
    "window.__callbackTest = {getOAuthGetParameters: getOAuthGetParameters, oAuthParamsToQuery: oAuthParamsToQuery}; window.CasdoorAuthCallback = {",
  );
  const window = {
    location: {
      origin: "https://id.example.test",
      protocol: "https:",
      hostname: "id.example.test",
      port: "",
    },
  };
  vm.runInNewContext(instrumented, {window, URL, URLSearchParams});

  const encoded = "client_id=client&response_type=code&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&scope=openid%20profile&state=caller%2Bstate&nonce=nonce&code_challenge_method=S256&code_challenge=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ&resource=https%3A%2F%2Fapi.example.test&response_mode=form_post&prompt=consent&max_age=0";
  const oauth = window.__callbackTest.getOAuthGetParameters(new URLSearchParams(encoded), encoded);
  const serialized = window.__callbackTest.oAuthParamsToQuery(oauth);
  const query = new URLSearchParams(serialized);

  assert.equal(query.get("state"), "caller+state");
  assert.equal(query.get("prompt"), "consent");
  assert.equal(query.get("maxAge"), "0");
  assert.equal(query.get("response_mode"), "form_post");
  assert.equal(query.get("resource"), "https://api.example.test");
});
