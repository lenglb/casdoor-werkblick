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
	"strings"
	"testing"
)

func TestOrganizationCredentialsNeverAppearInMaskedResponses(t *testing.T) {
	organization := &Organization{
		Owner:                  "admin",
		Name:                   "tenant",
		MasterPassword:         "master-password-sentinel",
		DefaultPassword:        "default-password-sentinel",
		MasterVerificationCode: "master-code-sentinel",
		PasswordObfuscatorKey:  "obfuscator-key-sentinel",
		PasswordSalt:           "password-salt-sentinel",
		KerberosKeytab:         "kerberos-keytab-sentinel",
	}

	masked, err := GetMaskedOrganization(true, organization)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(masked)
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{
		"master-password-sentinel", "default-password-sentinel", "master-code-sentinel",
		"obfuscator-key-sentinel", "password-salt-sentinel", "kerberos-keytab-sentinel",
	} {
		if strings.Contains(string(payload), sentinel) {
			t.Fatalf("masked organization exposed %q", sentinel)
		}
	}
	if organization.KerberosKeytab != "kerberos-keytab-sentinel" {
		t.Fatal("masking mutated the stored organization")
	}

	application := &Application{OrganizationObj: organization}
	applicationPayload, err := json.Marshal(GetMaskedApplication(application, ""))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(applicationPayload), "kerberos-keytab-sentinel") ||
		strings.Contains(string(applicationPayload), "obfuscator-key-sentinel") {
		t.Fatal("anonymous application response exposed organization credentials")
	}
}
