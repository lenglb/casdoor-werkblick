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

package controllers

import (
	"testing"

	"github.com/casdoor/casdoor/object"
)

func TestResolvePasswordSigninMethodFailsClosed(t *testing.T) {
	application := &object.Application{
		SigninMethods: []*object.SigninMethod{
			{Name: "Password", Rule: "Non-LDAP"},
			{Name: "LDAP", Rule: "All"},
		},
	}

	for _, method := range []string{"", "password", "Unknown", "Client credentials", " Password"} {
		if _, _, err := resolvePasswordSigninMethod(application, method); err == nil {
			t.Fatalf("signin method %q unexpectedly reached password authentication", method)
		}
	}
	if _, _, err := resolvePasswordSigninMethod(nil, "Password"); err == nil {
		t.Fatal("nil application unexpectedly reached password authentication")
	}
}

func TestResolvePasswordSigninMethodPreservesPasswordAndLdapRules(t *testing.T) {
	nonLdap := &object.Application{SigninMethods: []*object.SigninMethod{{Name: "Password", Rule: "Non-LDAP"}}}
	isLdap, passwordMayUseLdap, err := resolvePasswordSigninMethod(nonLdap, "Password")
	if err != nil || isLdap || passwordMayUseLdap {
		t.Fatalf("Non-LDAP password flow = ldap:%v passwordMayUseLdap:%v err:%v", isLdap, passwordMayUseLdap, err)
	}

	all := &object.Application{SigninMethods: []*object.SigninMethod{{Name: "Password", Rule: "All"}}}
	isLdap, passwordMayUseLdap, err = resolvePasswordSigninMethod(all, "Password")
	if err != nil || isLdap || !passwordMayUseLdap {
		t.Fatalf("All password flow = ldap:%v passwordMayUseLdap:%v err:%v", isLdap, passwordMayUseLdap, err)
	}

	ldap := &object.Application{SigninMethods: []*object.SigninMethod{{Name: "LDAP", Rule: "All"}}}
	isLdap, passwordMayUseLdap, err = resolvePasswordSigninMethod(ldap, "LDAP")
	if err != nil || !isLdap || passwordMayUseLdap {
		t.Fatalf("LDAP flow = ldap:%v passwordMayUseLdap:%v err:%v", isLdap, passwordMayUseLdap, err)
	}

	hidden := &object.Application{SigninMethods: []*object.SigninMethod{{Name: "Password", Rule: "Hide password"}}}
	if _, _, err = resolvePasswordSigninMethod(hidden, "Password"); err == nil {
		t.Fatal("hidden password method unexpectedly reached password authentication")
	}
}
