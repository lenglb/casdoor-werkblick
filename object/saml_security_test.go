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
	"encoding/json"
	"testing"
)

func TestSamlIdpIsExplicitlyOptInAndTenantBound(t *testing.T) {
	application := &Application{SamlReplyUrl: "https://sp.example.com/saml/acs"}
	if err := ValidateSamlIdpApplication(application); err == nil {
		t.Fatal("SAML was enabled by configuration side effects without explicit opt-in")
	}

	application.EnableSaml = true
	application.IsShared = true
	if err := ValidateSamlIdpApplication(application); err == nil {
		t.Fatal("shared application unexpectedly enabled as a SAML identity provider")
	}

	application.IsShared = false
	if err := ValidateSamlIdpApplication(application); err != nil {
		t.Fatalf("tenant-bound explicitly enabled SAML application rejected: %v", err)
	}

	var decoded Application
	if err := json.Unmarshal([]byte(`{"name":"oidc-only"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.EnableSaml {
		t.Fatal("application payload without enableSaml defaulted to enabled")
	}
}

func TestSamlReplyURLMustBeExplicitAndSecure(t *testing.T) {
	for _, replyURL := range []string{
		"",
		" https://sp.example.com/saml/acs",
		"/relative/acs",
		"http://sp.example.com/saml/acs",
		"https://user@sp.example.com/saml/acs",
		"https://sp.example.com/saml/acs#fragment",
		"javascript:alert(1)",
	} {
		application := &Application{EnableSaml: true, SamlReplyUrl: replyURL}
		if err := ValidateSamlIdpApplication(application); err == nil {
			t.Fatalf("unsafe SAML reply URL %q unexpectedly accepted", replyURL)
		}
	}

	for _, replyURL := range []string{
		"https://sp.example.com/saml/acs",
		"https://sp.example.com:8443/saml/acs?tenant=werkblick",
		"http://localhost:3000/saml/acs",
		"http://127.0.0.1:3000/saml/acs",
		"http://[::1]:3000/saml/acs",
	} {
		application := &Application{EnableSaml: true, SamlReplyUrl: replyURL}
		if err := ValidateSamlIdpApplication(application); err != nil {
			t.Fatalf("safe SAML reply URL %q rejected: %v", replyURL, err)
		}
	}
}

func TestSamlAssertionConsumerServiceURLRequiresExactMatch(t *testing.T) {
	application := &Application{EnableSaml: true, SamlReplyUrl: "https://sp.example.com/saml/acs"}
	got, err := ValidateSamlAssertionConsumerServiceURL(application, application.SamlReplyUrl)
	if err != nil || got != application.SamlReplyUrl {
		t.Fatalf("exact ACS match = %q, %v", got, err)
	}

	for _, requested := range []string{
		"",
		"https://attacker.example/saml/acs",
		"https://SP.example.com/saml/acs",
		"https://sp.example.com/saml/acs/",
		"https://sp.example.com/saml/acs?next=attacker",
	} {
		if _, err = ValidateSamlAssertionConsumerServiceURL(application, requested); err == nil {
			t.Fatalf("non-exact ACS %q unexpectedly accepted", requested)
		}
	}
}

func TestSamlAssertionConstructionChecksGateBeforeSigning(t *testing.T) {
	application := &Application{SamlReplyUrl: "https://sp.example.com/saml/acs"}
	if _, err := NewSamlResponse(application, &User{}, "https://idp.example.com", "", application.SamlReplyUrl, "issuer", "request", nil); err == nil {
		t.Fatal("disabled application reached SAML assertion construction")
	}
	if _, _, _, err := GetSamlResponse(application, &User{}, "not-a-saml-request", "idp.example.com"); err == nil {
		t.Fatal("disabled application reached SAML request parsing")
	}
	if _, err := NewSamlResponse11(application, &User{}, "request", "idp.example.com"); err == nil {
		t.Fatal("disabled application reached SAML 1.1 assertion construction")
	}
}
