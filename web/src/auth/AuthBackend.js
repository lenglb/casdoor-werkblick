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

import {authConfig} from "./Auth";
import * as Setting from "../Setting";

export function getAccount(query = "") {
  return fetch(`${authConfig.serverUrl}/api/get-account${query}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function signup(values, oAuthParams) {
  return fetch(`${authConfig.serverUrl}/api/signup${oAuthParamsToQuery(oAuthParams)}`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Content-Type": "application/json",
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getEmailAndPhone(organization, username) {
  return fetch(`${authConfig.serverUrl}/api/get-email-and-phone?organization=${organization}&username=${encodeURIComponent(username)}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then((res) => res.json());
}

export function casLoginParamsToQuery(casParams) {
  return `?type=${casParams?.type}&id=${casParams?.id}&redirectUri=${casParams?.service}`;
}

export function oAuthParamsToSearchParams(oAuthParams, overrides = {}) {
  const values = {...(oAuthParams || {}), ...overrides};
  const params = new URLSearchParams();
  const mappings = [
    ["clientId", values.clientId],
    ["responseType", values.responseType],
    ["redirectUri", values.redirectUri],
    ["type", values.type],
    ["scope", values.scope],
    ["state", values.state],
    ["nonce", values.nonce],
    ["code_challenge_method", values.challengeMethod],
    ["code_challenge", values.codeChallenge],
    ["resource", values.resource],
    ["response_mode", values.responseMode],
    ["prompt", values.prompt],
    ["maxAge", values.maxAge],
  ];

  mappings.forEach(([name, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      params.set(name, String(value));
    }
  });

  return params;
}

// WebAuthn is a two-request authentication ceremony. Build its OAuth query
// once so begin and finish cannot drift on nonce, state, PKCE, scope, prompt,
// max_age, resource, client, or redirect URI.
export function getWebAuthnSigninSearchParams(oAuthParams, responseType) {
  const normalizedResponseType = responseType || "login";
  if (normalizedResponseType === "code") {
    return oAuthParamsToSearchParams(oAuthParams, {
      responseType: normalizedResponseType,
      type: normalizedResponseType,
    });
  }

  return new URLSearchParams({responseType: normalizedResponseType});
}

export function oAuthParamsToQuery(oAuthParams, overrides = {}) {
  if ((oAuthParams === null || oAuthParams === undefined) && Object.keys(overrides).length === 0) {
    return "";
  }

  const query = oAuthParamsToSearchParams(oAuthParams, overrides).toString();
  return query === "" ? "" : `?${query}`;
}

export function getApplicationLogin(params) {
  let queryParams = "";
  if (params?.type === "cas") {
    queryParams = casLoginParamsToQuery(params);
  } else if (params?.type === "device") {
    queryParams = `?userCode=${params.userCode}&type=device`;
  } else {
    queryParams = oAuthParamsToQuery(params);
  }
  return fetch(`${authConfig.serverUrl}/api/get-app-login${queryParams}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function startDeviceLogin(clientId, scope) {
  return fetch(`${authConfig.serverUrl}/api/device-auth?client_id=${encodeURIComponent(clientId)}&scope=${encodeURIComponent(scope)}`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function pollDeviceLoginToken(clientId, deviceCode) {
  return fetch(`${authConfig.serverUrl}/api/login/oauth/access_token?client_id=${encodeURIComponent(clientId)}&grant_type=${encodeURIComponent("urn:ietf:params:oauth:grant-type:device_code")}&device_code=${encodeURIComponent(deviceCode)}`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function cancelDeviceLogin(userCode, cancelToken) {
  return fetch(`${authConfig.serverUrl}/api/cancel-device-auth?userCode=${encodeURIComponent(userCode)}&cancelToken=${encodeURIComponent(cancelToken)}`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function completeDeviceLogin(deviceCode, oAuthParams) {
  return fetch(`${authConfig.serverUrl}/api/device-auth-complete?deviceCode=${encodeURIComponent(deviceCode)}${oAuthParamsToQuery(oAuthParams).replace("?", "&")}`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function login(values, oAuthParams) {
  return fetch(`${authConfig.serverUrl}/api/login${oAuthParamsToQuery(oAuthParams)}`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Content-Type": "application/json",
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function loginCas(values, params) {
  return fetch(`${authConfig.serverUrl}/api/login?service=${params.service}`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Content-Type": "application/json",
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function logout() {
  return fetch(`${authConfig.serverUrl}/api/logout`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function unlink(values) {
  return fetch(`${authConfig.serverUrl}/api/unlink`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Content-Type": "application/json",
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getSamlLogin(providerId, relayState) {
  return fetch(`${authConfig.serverUrl}/api/get-saml-login?id=${providerId}&relayState=${relayState}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function loginWithSaml(values, param) {
  return fetch(`${authConfig.serverUrl}/api/login${param}`, {
    method: "POST",
    credentials: "include",
    body: JSON.stringify(values),
    headers: {
      "Content-Type": "application/json",
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getWechatMessageEvent(ticket) {
  return fetch(`${Setting.ServerUrl}/api/get-webhook-event?ticket=${ticket}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getWechatQRCode(providerId) {
  return fetch(`${Setting.ServerUrl}/api/get-qrcode?id=${providerId}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}

export function getCaptchaStatus(values) {
  return fetch(`${Setting.ServerUrl}/api/get-captcha-status?organization=${values["organization"]}&userId=${values["username"]}&application=${values["application"]}`, {
    method: "GET",
    credentials: "include",
    headers: {
      "Accept-Language": Setting.getAcceptLanguage(),
    },
  }).then(res => res.json());
}
