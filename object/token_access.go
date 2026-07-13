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

	"github.com/casdoor/casdoor/util"
)

// validateUserTokenAuthenticationPolicy applies the assurance requirement that
// must hold at every human-token issuance boundary. Authentication context is
// server-established evidence, while the user is freshly reloaded immediately
// before this function is called. Email verification is deliberately not a
// global OIDC gate: the signed email_verified claim reports the persisted
// state, while privileged operator access is enforced by the console gate.
func validateUserTokenAuthenticationPolicy(user *User, _ string, authenticationContext AuthenticationContext) *TokenError {
	if user == nil {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "token subject does not identify a user"}
	}
	preserved, err := PreserveAuthenticationContext(authenticationContext)
	if err != nil {
		return &TokenError{Error: InvalidGrant, ErrorDescription: fmt.Sprintf("authentication context is invalid: %s", err.Error())}
	}
	if preserved.Subject != user.GetId() {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "authentication context subject does not match the persisted user"}
	}
	if user.IsMfaEnabled() && GetAuthenticationContextClass(preserved.Amr) != AuthenticationContextClassAal2 {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "multi-factor authentication is required; authenticate again"}
	}
	return nil
}

// revalidateUserTokenAccess reloads a user and re-evaluates the durable access
// policy immediately before a user token is minted. A password, assertion,
// refresh token, or subject token proves authentication; it does not preserve
// authorization after an administrator offboards a user or changes an
// application's access policy.
func revalidateUserTokenAccess(application *Application, previouslyLoadedUser *User) (*User, *TokenError, error) {
	if application == nil {
		return nil, &TokenError{Error: InvalidClient, ErrorDescription: "application does not exist"}, nil
	}
	if previouslyLoadedUser == nil || previouslyLoadedUser.Owner == "" || previouslyLoadedUser.Name == "" {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "token subject does not identify a user"}, nil
	}

	user, err := getUser(previouslyLoadedUser.Owner, previouslyLoadedUser.Name)
	if err != nil {
		return nil, nil, err
	}
	if user == nil {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "the user no longer exists"}, nil
	}
	if user.Id == "" {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "the persisted user has no immutable subject ID"}, nil
	}
	// Do not let a deleted-and-recreated account inherit an old assertion,
	// refresh token, or subject token merely because the username was reused.
	if previouslyLoadedUser.Id != "" && user.Id != previouslyLoadedUser.Id {
		return nil, &TokenError{Error: InvalidGrant, ErrorDescription: "the token subject no longer identifies the persisted user"}, nil
	}
	tokenError, err := validateUserTokenAccess(application, user)
	if err != nil || tokenError != nil {
		return nil, tokenError, err
	}

	return user, nil, nil
}

// validateUserTokenAccess applies the current durable access policy to a user.
// Callers creating a user can use it before persistence to avoid creating an
// account that is already barred by application, organization, MFA, permission,
// or tag policy. Issuance paths must still reload and revalidate after any write.
func validateUserTokenAccess(application *Application, user *User) (*TokenError, error) {
	if application == nil {
		return &TokenError{Error: InvalidClient, ErrorDescription: "application does not exist"}, nil
	}
	if user == nil || user.Owner == "" || user.Name == "" || user.Id == "" {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "token subject does not identify a user"}, nil
	}
	if user.IsDeleted {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "the user has been deleted and cannot sign in"}, nil
	}
	if user.IsForbidden {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "the user is forbidden to sign in, please contact the administrator"}, nil
	}
	if application.DisableSignin {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "the application has disabled user sign-in"}, nil
	}

	organization, err := getOrganization(application.Owner, application.Organization)
	if err != nil {
		return nil, err
	}
	if organization == nil {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("the application organization %q no longer exists", application.Organization),
		}, nil
	}
	if organization.DisableSignin {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "the organization has disabled user sign-in"}, nil
	}
	if IsNeedPromptMfa(organization, user) {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "required MFA enrollment is incomplete; authenticate again"}, nil
	}

	allowed, err := CheckLoginPermission(user.GetId(), application)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return &TokenError{Error: InvalidGrant, ErrorDescription: "the user is not authorized to access this application"}, nil
	}
	if !user.IsGlobalAdmin() && !user.IsAdmin && len(application.Tags) > 0 && !util.HasTagInSlice(application.Tags, user.Tag) {
		return &TokenError{
			Error:            InvalidGrant,
			ErrorDescription: fmt.Sprintf("the user's tag %q is not allowed by the application", user.Tag),
		}, nil
	}

	return nil, nil
}
