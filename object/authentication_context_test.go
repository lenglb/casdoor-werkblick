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

import (
	"reflect"
	"strings"
	"testing"
)

func TestAuthenticationContextNormalize(t *testing.T) {
	input := AuthenticationContext{
		Subject:  "  werkblick/bernhard  ",
		AuthTime: 1_752_000_000,
		Amr:      []string{" pwd ", "", "otp", "pwd", " otp ", "webauthn"},
		Provider: "  casdoor  ",
	}

	got := input.Normalize()
	want := AuthenticationContext{
		Subject:  "werkblick/bernhard",
		AuthTime: 1_752_000_000,
		Amr:      []string{"pwd", "otp", "webauthn"},
		Provider: "casdoor",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize() = %#v, want %#v", got, want)
	}
	if input.Subject != "  werkblick/bernhard  " || input.Provider != "  casdoor  " {
		t.Fatal("Normalize() mutated scalar input fields")
	}
	if !reflect.DeepEqual(input.Amr, []string{" pwd ", "", "otp", "pwd", " otp ", "webauthn"}) {
		t.Fatal("Normalize() mutated the input AMR slice")
	}

	got.Amr[0] = "changed"
	if input.Amr[0] != " pwd " {
		t.Fatal("Normalize() returned an AMR slice that aliases the input")
	}
}

func TestAuthenticationContextNormalizePreservesFirstSeenAmrOrder(t *testing.T) {
	input := AuthenticationContext{
		Subject:  "werkblick/bernhard",
		AuthTime: 1_752_000_000,
		Amr:      []string{"pwd", "otp", "pwd", "mfa", "otp"},
	}

	want := []string{"pwd", "otp", "mfa"}
	for i := 0; i < 20; i++ {
		got := input.Normalize()
		if !reflect.DeepEqual(got.Amr, want) {
			t.Fatalf("Normalize() iteration %d AMR = %#v, want %#v", i, got.Amr, want)
		}
	}
}

func TestAuthenticationContextValidate(t *testing.T) {
	valid := AuthenticationContext{
		Subject:  "werkblick/bernhard",
		AuthTime: 1_752_000_000,
		Amr:      []string{"pwd", "otp"},
		Provider: "casdoor",
	}

	tests := []struct {
		name    string
		context AuthenticationContext
		wantErr string
	}{
		{name: "valid", context: valid},
		{name: "optional provider", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: valid.Amr}},
		{name: "empty subject", context: AuthenticationContext{AuthTime: valid.AuthTime, Amr: valid.Amr}, wantErr: "subject must not be empty"},
		{name: "unnormalized subject", context: AuthenticationContext{Subject: " user ", AuthTime: valid.AuthTime, Amr: valid.Amr}, wantErr: "subject must be normalized"},
		{name: "subject control character", context: AuthenticationContext{Subject: "user\nname", AuthTime: valid.AuthTime, Amr: valid.Amr}, wantErr: "subject must not contain control characters"},
		{name: "zero auth time", context: AuthenticationContext{Subject: valid.Subject, Amr: valid.Amr}, wantErr: "auth_time must be greater than zero"},
		{name: "negative auth time", context: AuthenticationContext{Subject: valid.Subject, AuthTime: -1, Amr: valid.Amr}, wantErr: "auth_time must be greater than zero"},
		{name: "nil amr", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime}, wantErr: "amr must not be empty"},
		{name: "empty amr value", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: []string{"pwd", ""}}, wantErr: "amr must not contain empty values"},
		{name: "unnormalized amr", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: []string{" pwd"}}, wantErr: "must be normalized"},
		{name: "amr internal whitespace", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: []string{"one time password"}}, wantErr: "must not contain whitespace or control characters"},
		{name: "amr control character", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: []string{"pwd\notp"}}, wantErr: "must not contain whitespace or control characters"},
		{name: "duplicate amr", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: []string{"pwd", "pwd"}}, wantErr: "is duplicated"},
		{name: "unnormalized provider", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: valid.Amr, Provider: " casdoor"}, wantErr: "provider must be normalized"},
		{name: "provider control character", context: AuthenticationContext{Subject: valid.Subject, AuthTime: valid.AuthTime, Amr: valid.Amr, Provider: "cas\ndoor"}, wantErr: "provider must not contain control characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.context.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() error = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuthenticationContextCloneDoesNotAliasAmr(t *testing.T) {
	original := AuthenticationContext{
		Subject:  "werkblick/bernhard",
		AuthTime: 1_752_000_000,
		Amr:      []string{"pwd", "otp"},
		Provider: "casdoor",
	}

	clone := original.Clone()
	clone.Amr[0] = "changed"

	if original.Amr[0] != "pwd" {
		t.Fatal("Clone() returned an AMR slice that aliases the original")
	}
	if clone.Subject != original.Subject || clone.AuthTime != original.AuthTime || clone.Provider != original.Provider {
		t.Fatalf("Clone() did not preserve scalar fields: got %#v, want %#v", clone, original)
	}
}

func TestAuthenticationContextClassIsDerivedConservatively(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		want    string
	}{
		{name: "password only", methods: []string{"pwd"}, want: AuthenticationContextClassAal1},
		{name: "LDAP is not a second factor", methods: []string{"pwd", "ldap"}, want: AuthenticationContextClassAal1},
		{name: "password and TOTP", methods: []string{"pwd", "otp"}, want: AuthenticationContextClassAal2},
		{name: "federated and RADIUS", methods: []string{"federated", "radius"}, want: AuthenticationContextClassAal2},
		{name: "recovery does not assert AAL2", methods: []string{"pwd", "recovery"}, want: AuthenticationContextClassAal1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetAuthenticationContextClass(tt.methods); got != tt.want {
				t.Fatalf("GetAuthenticationContextClass() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPreserveAuthenticationContext(t *testing.T) {
	original := AuthenticationContext{
		Subject:  "  werkblick/bernhard ",
		AuthTime: 1_752_000_000,
		Amr:      []string{" pwd ", "otp", "pwd"},
		Provider: " casdoor ",
	}

	preserved, err := PreserveAuthenticationContext(original)
	if err != nil {
		t.Fatalf("PreserveAuthenticationContext() error = %v", err)
	}
	want := AuthenticationContext{
		Subject:  "werkblick/bernhard",
		AuthTime: original.AuthTime,
		Amr:      []string{"pwd", "otp"},
		Provider: "casdoor",
	}
	if !reflect.DeepEqual(preserved, want) {
		t.Fatalf("PreserveAuthenticationContext() = %#v, want %#v", preserved, want)
	}

	preserved.Amr[0] = "changed"
	if original.Amr[0] != " pwd " {
		t.Fatal("PreserveAuthenticationContext() returned an AMR slice that aliases the input")
	}
}

func TestPreserveAuthenticationContextRejectsInvalidContext(t *testing.T) {
	preserved, err := PreserveAuthenticationContext(AuthenticationContext{
		Subject: "werkblick/bernhard",
		Amr:     []string{"pwd"},
	})
	if err == nil {
		t.Fatal("PreserveAuthenticationContext() error = nil, want invalid auth_time error")
	}
	if !reflect.DeepEqual(preserved, AuthenticationContext{}) {
		t.Fatalf("PreserveAuthenticationContext() = %#v, want zero value on error", preserved)
	}
}

func TestTokenAuthenticationContextRoundTrip(t *testing.T) {
	token := &Token{
		Organization: "werkblick",
		User:         "bernhard",
	}
	context := AuthenticationContext{
		Subject:  "werkblick/bernhard",
		AuthTime: 1_752_000_000,
		Amr:      []string{"pwd", "otp"},
		Provider: "casdoor",
	}

	if err := token.SetAuthenticationContext(context); err != nil {
		t.Fatalf("SetAuthenticationContext() error = %v", err)
	}
	got, err := token.GetAuthenticationContext()
	if err != nil {
		t.Fatalf("GetAuthenticationContext() error = %v", err)
	}
	if !reflect.DeepEqual(got, context) {
		t.Fatalf("GetAuthenticationContext() = %#v, want %#v", got, context)
	}

	got.Amr[0] = "changed"
	if token.AuthenticationMethods[0] != "pwd" {
		t.Fatal("GetAuthenticationContext() returned an AMR slice that aliases token state")
	}
}

func TestTokenAuthenticationContextRejectsSubjectMismatch(t *testing.T) {
	token := &Token{
		Organization: "werkblick",
		User:         "bernhard",
	}
	err := token.SetAuthenticationContext(AuthenticationContext{
		Subject:  "werkblick/mallory",
		AuthTime: 1_752_000_000,
		Amr:      []string{"pwd"},
	})
	if err == nil || !strings.Contains(err.Error(), "does not match token subject") {
		t.Fatalf("SetAuthenticationContext() error = %v, want subject mismatch", err)
	}
}
