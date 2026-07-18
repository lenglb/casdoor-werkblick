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
import test from "node:test";
import {createOtpAutoSubmitter, createSubmissionGuard, shouldAutoSubmitOtp} from "./MfaSubmission.mjs";

test("MFA submission guard admits exactly one in-flight request", () => {
  const guard = createSubmissionGuard();

  assert.equal(guard.tryStart(), true);
  assert.equal(guard.tryStart(), false);
  guard.finish();
  assert.equal(guard.tryStart(), true);
});

test("OTP auto-submit accepts one new complete passcode", () => {
  assert.equal(shouldAutoSubmitOtp("12345", ""), false);
  assert.equal(shouldAutoSubmitOtp("123456", ""), true);
  assert.equal(shouldAutoSubmitOtp("123456", "123456"), false);
  assert.equal(shouldAutoSubmitOtp("654321", "123456"), true);
});

test("OTP auto-submitter invokes submit once per complete passcode and stays locked while disabled", () => {
  let submissions = 0;
  const autoSubmit = createOtpAutoSubmitter(() => {
    submissions += 1;
  });

  assert.equal(autoSubmit("12345"), false);
  assert.equal(autoSubmit("123456"), true);
  assert.equal(autoSubmit("123456"), false);
  assert.equal(autoSubmit("654321", true), false);
  assert.equal(autoSubmit("654321"), true);
  assert.equal(submissions, 2);
});
