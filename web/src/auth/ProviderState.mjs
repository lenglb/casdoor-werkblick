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

const providerStateNoncePattern = /^[a-f0-9]{64}$/;
const providerStateStoragePrefix = "casdoor_provider_state_";

function encodeProviderStatePayload(query) {
  return btoa(encodeURIComponent(query))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function decodeProviderStatePayload(payload) {
  const padded = payload.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payload.length / 4) * 4, "=");
  return decodeURIComponent(atob(padded));
}

export function createProviderState(providerState, applicationName, providerName, method, isShortState, location, storage) {
  if (!providerStateNoncePattern.test(providerState)) {
    throw new Error("A valid server-issued provider state is required");
  }
  let query = location.search;
  query = `${query}&application=${encodeURIComponent(applicationName)}&provider=${encodeURIComponent(providerName)}&method=${method}`;
  if (method === "link") {
    query = `${query}&from=${encodeURIComponent(location.pathname)}`;
  }

  if (!isShortState) {
    return `${providerState}.${encodeProviderStatePayload(query)}`;
  }
  storage.setItem(`${providerStateStoragePrefix}${providerState}`, query);
  return providerState;
}

export function readProviderState(state, storage) {
  if (typeof state !== "string" || state.trim() !== state || state === "") {
    throw new Error("Provider state is missing");
  }
  const parts = state.split(".");
  if (parts.length > 2 || !providerStateNoncePattern.test(parts[0])) {
    throw new Error("Provider state is malformed");
  }
  if (parts.length === 2) {
    if (parts[1] === "") {
      throw new Error("Provider state payload is missing");
    }
    return decodeProviderStatePayload(parts[1]);
  }

  const query = storage.getItem(`${providerStateStoragePrefix}${state}`);
  if (query === null) {
    throw new Error("Short provider state is not available in this browser session");
  }
  return query;
}
