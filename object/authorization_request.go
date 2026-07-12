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
	"time"
)

const (
	CurrentAuthenticationContextSessionKey = "currentAuthenticationContext"
	PendingAuthenticationSessionKey        = "pendingAuthentication"
)

// AuthorizationRequest is the server-captured OAuth request that an
// authentication event is authorizing. Keeping it in the server-side session
// prevents the MFA and consent follow-up requests from replacing client,
// redirect, nonce, PKCE, scope, or resource values.
type AuthorizationRequest struct {
	ClientId        string `json:"client_id"`
	ResponseType    string `json:"response_type"`
	ResponseMode    string `json:"response_mode,omitempty"`
	RedirectUri     string `json:"redirect_uri"`
	Scope           string `json:"scope,omitempty"`
	State           string `json:"state,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
	ChallengeMethod string `json:"code_challenge_method,omitempty"`
	CodeChallenge   string `json:"code_challenge,omitempty"`
	Resource        string `json:"resource,omitempty"`
	Prompt          string `json:"prompt,omitempty"`
	MaxAge          *int64 `json:"max_age,omitempty"`
}

// Clone returns an alias-free copy of the request.
func (request AuthorizationRequest) Clone() AuthorizationRequest {
	res := request
	if request.MaxAge != nil {
		maxAge := *request.MaxAge
		res.MaxAge = &maxAge
	}
	return res
}

// Equal reports whether two captured requests describe the exact same OAuth
// transaction. It is used to fail closed when concurrent browser tabs overwrite
// a session's pending authentication.
func (request AuthorizationRequest) Equal(other AuthorizationRequest) bool {
	if request.ClientId != other.ClientId ||
		request.ResponseType != other.ResponseType ||
		request.ResponseMode != other.ResponseMode ||
		request.RedirectUri != other.RedirectUri ||
		request.Scope != other.Scope ||
		request.State != other.State ||
		request.Nonce != other.Nonce ||
		request.ChallengeMethod != other.ChallengeMethod ||
		request.CodeChallenge != other.CodeChallenge ||
		request.Resource != other.Resource ||
		request.Prompt != other.Prompt {
		return false
	}
	if request.MaxAge == nil || other.MaxAge == nil {
		return request.MaxAge == nil && other.MaxAge == nil
	}
	return *request.MaxAge == *other.MaxAge
}

func (request AuthorizationRequest) Validate() error {
	if strings.TrimSpace(request.ClientId) == "" {
		return fmt.Errorf("authorization request client_id must not be empty")
	}
	if request.ResponseType != "code" {
		return fmt.Errorf("authorization request response_type %q is not supported", request.ResponseType)
	}
	if request.ResponseMode != "" && request.ResponseMode != "query" && request.ResponseMode != "form_post" {
		return fmt.Errorf("authorization request response_mode %q is not supported", request.ResponseMode)
	}
	if strings.TrimSpace(request.RedirectUri) == "" {
		return fmt.Errorf("authorization request redirect_uri must not be empty")
	}
	if (request.ChallengeMethod == "") != (request.CodeChallenge == "") {
		return fmt.Errorf("authorization request code_challenge and code_challenge_method must be provided together")
	}
	if request.ChallengeMethod != "" && request.ChallengeMethod != "S256" {
		return fmt.Errorf("authorization request code_challenge_method must be S256")
	}
	if request.CodeChallenge != "" {
		if len(request.CodeChallenge) < 43 || len(request.CodeChallenge) > 128 {
			return fmt.Errorf("authorization request code_challenge must be between 43 and 128 characters")
		}
		for i := 0; i < len(request.CodeChallenge); i++ {
			if !isPkceUnreserved(request.CodeChallenge[i]) {
				return fmt.Errorf("authorization request code_challenge contains an invalid character")
			}
		}
	}
	if request.MaxAge != nil && *request.MaxAge < 0 {
		return fmt.Errorf("authorization request max_age must not be negative")
	}

	prompts, err := request.PromptValues()
	if err != nil {
		return err
	}
	if slices.Contains(prompts, "none") && len(prompts) != 1 {
		return fmt.Errorf("authorization request prompt none cannot be combined with other values")
	}
	return nil
}

func isPkceUnreserved(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '-' || value == '.' || value == '_' || value == '~'
}

func (request AuthorizationRequest) PromptValues() ([]string, error) {
	if strings.TrimSpace(request.Prompt) == "" {
		return nil, nil
	}

	allowed := map[string]struct{}{
		"none": {}, "login": {}, "consent": {}, "select_account": {},
	}
	res := []string{}
	seen := map[string]struct{}{}
	for _, prompt := range strings.Fields(request.Prompt) {
		if _, ok := allowed[prompt]; !ok {
			return nil, fmt.Errorf("authorization request prompt value %q is not supported", prompt)
		}
		if _, ok := seen[prompt]; ok {
			continue
		}
		seen[prompt] = struct{}{}
		res = append(res, prompt)
	}
	return res, nil
}

func (request AuthorizationRequest) RequiresFreshAuthentication(authenticationContext AuthenticationContext, now int64) bool {
	prompts, err := request.PromptValues()
	if err != nil {
		return true
	}
	if slices.Contains(prompts, "login") || slices.Contains(prompts, "select_account") {
		return true
	}
	return request.ExceedsMaxAge(authenticationContext, now)
}

// ExceedsMaxAge checks only the OIDC max_age constraint. It is suitable for
// continuations such as consent, where an earlier prompt=login has already
// been satisfied by the authentication event bound to the transaction.
func (request AuthorizationRequest) ExceedsMaxAge(authenticationContext AuthenticationContext, now int64) bool {
	if request.MaxAge == nil {
		return false
	}
	if authenticationContext.AuthTime <= 0 || authenticationContext.AuthTime > now {
		return true
	}
	return now-authenticationContext.AuthTime > *request.MaxAge
}

// PendingAuthentication binds verified primary authentication evidence to the
// exact OAuth request that is waiting for MFA or consent.
type PendingAuthentication struct {
	Context       AuthenticationContext `json:"context"`
	Request       *AuthorizationRequest `json:"request,omitempty"`
	FlowType      string                `json:"flow_type"`
	ApplicationId string                `json:"application_id"`
	UserCode      string                `json:"user_code,omitempty"`
	TransactionId string                `json:"transaction_id"`
	CreatedAt     int64                 `json:"created_at"`
	ExpiresAt     int64                 `json:"expires_at"`
}

func (pending PendingAuthentication) Preserve() (PendingAuthentication, error) {
	context, err := PreserveAuthenticationContext(pending.Context)
	if err != nil {
		return PendingAuthentication{}, err
	}
	switch pending.FlowType {
	case "login", "code", "token", "id_token", "saml", "cas", "device":
	default:
		return PendingAuthentication{}, fmt.Errorf("pending authentication flow type %q is invalid", pending.FlowType)
	}
	if strings.TrimSpace(pending.ApplicationId) == "" {
		return PendingAuthentication{}, fmt.Errorf("pending authentication application must not be empty")
	}
	if strings.TrimSpace(pending.TransactionId) == "" {
		return PendingAuthentication{}, fmt.Errorf("pending authentication transaction id must not be empty")
	}
	if pending.CreatedAt <= 0 || pending.ExpiresAt <= pending.CreatedAt {
		return PendingAuthentication{}, fmt.Errorf("pending authentication lifetime is invalid")
	}
	if time.Now().Unix() > pending.ExpiresAt {
		return PendingAuthentication{}, fmt.Errorf("pending authentication has expired")
	}
	var request *AuthorizationRequest
	if pending.Request != nil {
		if err = pending.Request.Validate(); err != nil {
			return PendingAuthentication{}, err
		}
		cloned := pending.Request.Clone()
		request = &cloned
	}
	if pending.FlowType == "code" && request == nil {
		return PendingAuthentication{}, fmt.Errorf("pending code authentication requires an OAuth request")
	}
	if pending.FlowType != "code" && request != nil {
		return PendingAuthentication{}, fmt.Errorf("pending non-code authentication must not contain an OAuth request")
	}
	if pending.FlowType == "device" && strings.TrimSpace(pending.UserCode) == "" {
		return PendingAuthentication{}, fmt.Errorf("pending device authentication requires a user code")
	}
	if pending.FlowType != "device" && pending.UserCode != "" {
		return PendingAuthentication{}, fmt.Errorf("pending non-device authentication must not contain a user code")
	}

	return PendingAuthentication{
		Context:       context,
		Request:       request,
		FlowType:      pending.FlowType,
		ApplicationId: pending.ApplicationId,
		UserCode:      pending.UserCode,
		TransactionId: pending.TransactionId,
		CreatedAt:     pending.CreatedAt,
		ExpiresAt:     pending.ExpiresAt,
	}, nil
}
