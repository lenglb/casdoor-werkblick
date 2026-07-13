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
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const (
	dpopMaxAgeSeconds        = 300
	dpopMaxFutureSkewSeconds = 30
)

// DPoPProofClaims represents the payload claims of a DPoP proof JWT (RFC 9449).
type DPoPProofClaims struct {
	Jti string `json:"jti"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Ath string `json:"ath,omitempty"`
	jwt.RegisteredClaims
}

// ValidateDPoPProof validates a DPoP proof JWT as specified in RFC 9449.
//
//   - proofToken: the compact-serialized DPoP proof JWT from the DPoP HTTP header
//   - method:     the HTTP request method (e.g., "POST", "GET")
//   - htu:        the HTTP request URL without query string or fragment
//   - accessToken: the access token string; empty at the token endpoint,
//     non-empty at protected resource endpoints (enables ath claim validation)
//
// On success it returns the base64url-encoded SHA-256 JWK thumbprint (jkt) of
// the DPoP public key embedded in the proof header.
func ValidateDPoPProof(proofToken, method, htu, accessToken string) (string, error) {
	return validateDPoPProofAt(proofToken, method, htu, accessToken, time.Now())
}

func validateDPoPProofAt(proofToken, method, htu, accessToken string, now time.Time) (string, error) {
	parts := strings.Split(proofToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid DPoP proof JWT format")
	}

	// Decode and inspect the JOSE header before signature verification.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode DPoP proof header: %w", err)
	}

	var header struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("failed to parse DPoP proof header: %w", err)
	}

	// typ MUST be exactly "dpop+jwt" (RFC 9449 §4.2).
	if header.Typ != "dpop+jwt" {
		return "", fmt.Errorf("DPoP proof typ must be \"dpop+jwt\", got %q", header.Typ)
	}

	// alg MUST identify an asymmetric digital signature algorithm;
	// symmetric algorithms (HS*) are explicitly forbidden (RFC 9449 §4.2).
	if header.Alg == "" || strings.HasPrefix(header.Alg, "HS") {
		return "", fmt.Errorf("DPoP proof must use an asymmetric algorithm, got %q", header.Alg)
	}

	// jwk MUST be present (RFC 9449 §4.2).
	if len(header.JWK) == 0 {
		return "", fmt.Errorf("DPoP proof header must contain the jwk claim")
	}

	var jwkKey jose.JSONWebKey
	if err = jwkKey.UnmarshalJSON(header.JWK); err != nil {
		return "", fmt.Errorf("failed to parse DPoP JWK: %w", err)
	}

	// Compute the JWK SHA-256 thumbprint per RFC 7638.
	thumbprintBytes, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute DPoP JWK thumbprint: %w", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumbprintBytes)

	// Verify the proof's signature using the public key embedded in the header.
	// WithoutClaimsValidation is used so that we can perform all claim checks
	// ourselves (jwt library exp/nbf validation is not appropriate here).
	t, err := jwt.ParseWithClaims(proofToken, &DPoPProofClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwkKey.Key, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		return "", fmt.Errorf("DPoP proof signature verification failed: %w", err)
	}
	if !t.Valid {
		return "", fmt.Errorf("DPoP proof signature verification failed")
	}

	claims, ok := t.Claims.(*DPoPProofClaims)
	if !ok {
		return "", fmt.Errorf("failed to parse DPoP proof claims")
	}

	// htm MUST match the HTTP request method (RFC 9449 §4.2).
	if claims.Htm != method {
		return "", fmt.Errorf("DPoP proof htm %q does not match request method %q", claims.Htm, method)
	}

	// Only the URI scheme and host are case-insensitive. Path, escaped path and
	// query data retain their exact spelling so equivalent-looking request
	// variants cannot bypass proof replay detection.
	proofHtu, err := normalizeDPoPTargetURI(claims.Htu)
	if err != nil {
		return "", fmt.Errorf("invalid DPoP proof htu: %w", err)
	}
	requestHtu, err := normalizeDPoPTargetURI(htu)
	if err != nil {
		return "", fmt.Errorf("invalid DPoP request URL: %w", err)
	}
	if proofHtu != requestHtu {
		return "", fmt.Errorf("DPoP proof htu %q does not match request URL %q", claims.Htu, htu)
	}

	// iat MUST be present and within the acceptable time window (RFC 9449 §4.2).
	if claims.IssuedAt == nil {
		return "", fmt.Errorf("DPoP proof missing iat claim")
	}
	issuedAt := claims.IssuedAt.Time
	maxFutureTime := now.Add(time.Duration(dpopMaxFutureSkewSeconds) * time.Second)
	if issuedAt.After(maxFutureTime) {
		return "", fmt.Errorf("DPoP proof iat is more than %d seconds in the future", dpopMaxFutureSkewSeconds)
	}
	proofExpiresAt := issuedAt.Add(time.Duration(dpopMaxAgeSeconds) * time.Second)
	replayTtl := proofExpiresAt.Sub(now)
	if replayTtl <= 0 {
		return "", fmt.Errorf("DPoP proof iat is outside the acceptable time window (%d seconds)", dpopMaxAgeSeconds)
	}

	// jti MUST be present to support replay detection (RFC 9449 §4.2).
	if claims.Jti == "" {
		return "", fmt.Errorf("DPoP proof missing jti claim")
	}

	// ath MUST be validated at protected resource endpoints (RFC 9449 §4.2).
	// It is the base64url-encoded SHA-256 hash of the ASCII access token string.
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		expectedAth := base64.RawURLEncoding.EncodeToString(hash[:])
		if claims.Ath != expectedAth {
			return "", fmt.Errorf("DPoP proof ath claim does not match access token hash")
		}
	}

	// A proof identity must not depend on request spelling. In particular, host
	// case or default-port variants must resolve to the same replay marker.
	replayKeyInput := strings.Join([]string{jkt, claims.Jti}, "\x00")
	replayKeyHash := sha256.Sum256([]byte(replayKeyInput))
	replayKey := base64.RawURLEncoding.EncodeToString(replayKeyHash[:])
	if err = useDPoPProofOnce(replayKey, replayTtl); err != nil {
		return "", err
	}

	return jkt, nil
}

func normalizeDPoPTargetURI(rawUri string) (string, error) {
	parsedUri, err := url.Parse(rawUri)
	if err != nil {
		return "", err
	}
	if parsedUri.Opaque != "" || parsedUri.Scheme == "" || parsedUri.Host == "" {
		return "", fmt.Errorf("target URI must be an absolute hierarchical URI")
	}
	if parsedUri.User != nil {
		return "", fmt.Errorf("target URI must not contain user information")
	}
	if parsedUri.Fragment != "" {
		return "", fmt.Errorf("target URI must not contain a fragment")
	}

	scheme := strings.ToLower(parsedUri.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("target URI scheme must be http or https")
	}

	hostname := strings.ToLower(parsedUri.Hostname())
	if hostname == "" {
		return "", fmt.Errorf("target URI host must not be empty")
	}
	port := parsedUri.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	authority := hostname
	if port != "" {
		authority = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}

	escapedPath := parsedUri.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}

	res := scheme + "://" + authority + escapedPath
	if parsedUri.ForceQuery || parsedUri.RawQuery != "" {
		res += "?" + parsedUri.RawQuery
	}
	return res, nil
}

// GetDPoPHtu constructs the full DPoP htu URL for a given host and path.
// It uses the same origin-detection logic as the rest of the backend.
func GetDPoPHtu(host, path string) string {
	_, originBackend := getOriginFromHost(host)
	return originBackend + path
}
