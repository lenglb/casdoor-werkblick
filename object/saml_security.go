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
	"net"
	"net/url"
	"strings"
)

// ValidateSamlIdpApplication is the common fail-closed gate for every SAML IdP
// surface. SAML is deliberately opt-in because an OIDC-only application must
// never become an assertion issuer merely by having a certificate.
func ValidateSamlIdpApplication(application *Application) error {
	if application == nil {
		return fmt.Errorf("SAML application is missing")
	}
	if !application.EnableSaml {
		return fmt.Errorf("SAML identity provider is not enabled for the application")
	}
	// A shared application can be resolved in the context of several
	// organizations. That ambiguity is unsafe for a signed SAML assertion, so a
	// SAML IdP must be tenant-bound.
	if application.IsShared {
		return fmt.Errorf("SAML identity provider cannot be enabled for a shared application")
	}
	if err := validateSamlReplyURL(application.SamlReplyUrl); err != nil {
		return err
	}
	return nil
}

func validateSamlReplyURL(replyURL string) error {
	if replyURL == "" || strings.TrimSpace(replyURL) != replyURL {
		return fmt.Errorf("SAML reply URL must be configured exactly")
	}

	parsed, err := url.Parse(replyURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("SAML reply URL must be an absolute URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("SAML reply URL must not contain user information or a fragment")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		hostname := strings.ToLower(parsed.Hostname())
		ip := net.ParseIP(hostname)
		if hostname == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}

	return fmt.Errorf("SAML reply URL must use HTTPS (HTTP is allowed only for loopback development)")
}

// ValidateSamlAssertionConsumerServiceURL requires the request to carry the
// exact ACS URL registered on the application. It intentionally performs no
// normalization: case, slash, query, port, and encoding differences are a
// mismatch rather than a chance to redirect an assertion.
func ValidateSamlAssertionConsumerServiceURL(application *Application, requestedURL string) (string, error) {
	if err := ValidateSamlIdpApplication(application); err != nil {
		return "", err
	}
	if requestedURL == "" {
		return "", fmt.Errorf("SAML request is missing AssertionConsumerServiceURL")
	}
	if requestedURL != application.SamlReplyUrl {
		return "", fmt.Errorf("SAML AssertionConsumerServiceURL does not exactly match the registered reply URL")
	}
	return application.SamlReplyUrl, nil
}
