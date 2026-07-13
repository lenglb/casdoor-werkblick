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

package object

import "testing"

func TestIsRequiredMfaTypeUsesUserOverrideAndEnrollmentState(t *testing.T) {
	organization := &Organization{MfaItems: []*MfaItem{
		{Name: TotpType, Rule: "Required"},
		{Name: EmailType, Rule: "Optional"},
	}}
	user := &User{}
	if !IsRequiredMfaType(organization, user, TotpType) {
		t.Fatal("missing required TOTP was not detected")
	}
	if IsRequiredMfaType(organization, user, EmailType) {
		t.Fatal("optional email MFA was treated as required")
	}

	user.TotpSecret = "enrolled"
	if IsRequiredMfaType(organization, user, TotpType) {
		t.Fatal("enrolled required TOTP was still reported as missing")
	}

	user.MfaItems = []*MfaItem{{Name: EmailType, Rule: "Required"}}
	user.MfaEmailEnabled = false
	if !IsRequiredMfaType(organization, user, EmailType) {
		t.Fatal("user-level required MFA override was not applied")
	}
	if IsRequiredMfaType(organization, user, TotpType) {
		t.Fatal("organization rule leaked through user-level override")
	}
}

func TestMfaEnabledStateDoesNotDependOnPreferredType(t *testing.T) {
	user := &User{TotpSecret: "enrolled", PreferredMfaType: ""}
	if !user.IsMfaEnabled() {
		t.Fatal("enrolled TOTP was bypassed because preferredMfaType is empty")
	}

	user = &User{PreferredMfaType: "totp"}
	if user.IsMfaEnabled() {
		t.Fatal("preferredMfaType without enrolled factor was treated as MFA")
	}
}

func TestHardenedMfaPolicyAcceptsOnlyTotp(t *testing.T) {
	if err := ValidateHardenedMfaItems([]*MfaItem{{Name: TotpType, Rule: "Required"}}); err != nil {
		t.Fatalf("valid TOTP policy failed: %v", err)
	}
	for _, items := range [][]*MfaItem{
		{{Name: EmailType, Rule: "Required"}},
		{{Name: PushType, Rule: "Optional"}},
		{{Name: TotpType, Rule: "invalid"}},
		{{Name: TotpType, Rule: "Optional"}, {Name: TotpType, Rule: "Required"}},
		{nil},
	} {
		if err := ValidateHardenedMfaItems(items); err == nil {
			t.Fatalf("unsafe MFA policy was accepted: %#v", items)
		}
	}
}
