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
	"fmt"
	"slices"
	"strings"
	"unicode"
)

const (
	AuthenticationContextClassAal1 = "urn:werkblick:acr:aal1"
	AuthenticationContextClassAal2 = "urn:werkblick:acr:aal2"
)

// GetAuthenticationContextClass derives a conservative ACR from verified AMR
// evidence. We never assert AAL3 because this flow does not retain enough
// authenticator-attestation detail to make that claim safely.
func GetAuthenticationContextClass(methods []string) string {
	hasPrimary := false
	hasIndependentSecondFactor := false
	for _, method := range methods {
		switch method {
		case "pwd", "master_password", "webauthn", "kerberos", "federated", "face", "email", "sms":
			hasPrimary = true
		}
		switch method {
		case "otp", "radius":
			hasIndependentSecondFactor = true
		}
	}
	if hasPrimary && hasIndependentSecondFactor {
		return AuthenticationContextClassAal2
	}
	return AuthenticationContextClassAal1
}

// AuthenticationContext contains authentication evidence established by the
// authorization server. Values in this type must only be produced from
// successfully verified server-side authentication events, never copied from
// OAuth request parameters or client-submitted sign-in labels.
type AuthenticationContext struct {
	Subject  string   `json:"sub"`
	AuthTime int64    `json:"auth_time"`
	Amr      []string `json:"amr"`
	Provider string   `json:"provider,omitempty"`
}

// Normalize returns a canonical deep copy of the authentication context. AMR
// values are trimmed, empty values are removed, and duplicates are removed
// while preserving the order in which the authentication methods occurred.
func (context AuthenticationContext) Normalize() AuthenticationContext {
	res := AuthenticationContext{
		Subject:  strings.TrimSpace(context.Subject),
		AuthTime: context.AuthTime,
		Provider: strings.TrimSpace(context.Provider),
		Amr:      make([]string, 0, len(context.Amr)),
	}

	seen := make(map[string]struct{}, len(context.Amr))
	for _, method := range context.Amr {
		method = strings.TrimSpace(method)
		if method == "" {
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}

		seen[method] = struct{}{}
		res.Amr = append(res.Amr, method)
	}

	return res
}

// Validate checks that the context is complete and canonical. Call Normalize
// before Validate when accepting a context assembled from multiple trusted
// server-side authentication steps.
func (context AuthenticationContext) Validate() error {
	if context.Subject == "" {
		return fmt.Errorf("authentication context subject must not be empty")
	}
	if strings.TrimSpace(context.Subject) != context.Subject {
		return fmt.Errorf("authentication context subject must be normalized")
	}
	if containsControlCharacter(context.Subject) {
		return fmt.Errorf("authentication context subject must not contain control characters")
	}
	if context.AuthTime <= 0 {
		return fmt.Errorf("authentication context auth_time must be greater than zero")
	}
	if len(context.Amr) == 0 {
		return fmt.Errorf("authentication context amr must not be empty")
	}

	seen := make(map[string]struct{}, len(context.Amr))
	for _, method := range context.Amr {
		if method == "" {
			return fmt.Errorf("authentication context amr must not contain empty values")
		}
		if strings.TrimSpace(method) != method {
			return fmt.Errorf("authentication context amr value %q must be normalized", method)
		}
		if strings.IndexFunc(method, unicode.IsSpace) >= 0 || containsControlCharacter(method) {
			return fmt.Errorf("authentication context amr value %q must not contain whitespace or control characters", method)
		}
		if _, ok := seen[method]; ok {
			return fmt.Errorf("authentication context amr value %q is duplicated", method)
		}
		seen[method] = struct{}{}
	}

	if strings.TrimSpace(context.Provider) != context.Provider {
		return fmt.Errorf("authentication context provider must be normalized")
	}
	if containsControlCharacter(context.Provider) {
		return fmt.Errorf("authentication context provider must not contain control characters")
	}

	return nil
}

// Clone returns a deep copy so callers cannot mutate the context's AMR
// evidence through a shared slice.
func (context AuthenticationContext) Clone() AuthenticationContext {
	res := context
	res.Amr = slices.Clone(context.Amr)
	return res
}

func (context AuthenticationContext) Equal(other AuthenticationContext) bool {
	return context.Subject == other.Subject &&
		context.AuthTime == other.AuthTime &&
		context.Provider == other.Provider &&
		slices.Equal(context.Amr, other.Amr)
}

// PreserveAuthenticationContext returns a normalized, validated deep copy of
// existing authentication evidence. It is intended for boundaries that must
// retain the original authentication event, such as authorization-code and
// refresh-token issuance; it deliberately does not advance AuthTime or add AMR
// values.
func PreserveAuthenticationContext(context AuthenticationContext) (AuthenticationContext, error) {
	preserved := context.Normalize()
	if err := preserved.Validate(); err != nil {
		return AuthenticationContext{}, err
	}

	return preserved.Clone(), nil
}

func containsControlCharacter(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
