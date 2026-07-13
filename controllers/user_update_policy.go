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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/object"
)

type userUpdateField struct {
	jsonName        string
	column          string
	accountItemName string
}

// Self-service is intentionally limited to profile data. Authentication
// credentials, MFA/WebAuthn material, verification flags, provider/LDAP
// links, authorization data, and system-maintained fields use purpose-built
// endpoints and never pass through the generic user update API.
var selfUserUpdateFields = []userUpdateField{
	{jsonName: "displayName", column: "display_name", accountItemName: "Display name"},
	{jsonName: "firstName", column: "first_name", accountItemName: "First name"},
	{jsonName: "lastName", column: "last_name", accountItemName: "Last name"},
	{jsonName: "avatar", column: "avatar", accountItemName: "Avatar"},
	{jsonName: "avatarType", column: "avatar_type", accountItemName: "Avatar"},
	{jsonName: "isDefaultAvatar", column: "is_default_avatar", accountItemName: "Avatar"},
	{jsonName: "email", column: "email", accountItemName: "Email"},
	{jsonName: "phone", column: "phone", accountItemName: "Phone"},
	{jsonName: "countryCode", column: "country_code", accountItemName: "Country code"},
	{jsonName: "region", column: "region", accountItemName: "Country/Region"},
	{jsonName: "location", column: "location", accountItemName: "Location"},
	{jsonName: "address", column: "address", accountItemName: "Address"},
	{jsonName: "addresses", column: "addresses", accountItemName: "Addresses"},
	{jsonName: "affiliation", column: "affiliation", accountItemName: "Affiliation"},
	{jsonName: "title", column: "title", accountItemName: "Title"},
	{jsonName: "idCardType", column: "id_card_type", accountItemName: "ID card type"},
	{jsonName: "idCard", column: "id_card", accountItemName: "ID card"},
	{jsonName: "realName", column: "real_name", accountItemName: "Real name"},
	{jsonName: "homepage", column: "homepage", accountItemName: "Homepage"},
	{jsonName: "bio", column: "bio", accountItemName: "Bio"},
	{jsonName: "language", column: "language", accountItemName: "Language"},
	{jsonName: "gender", column: "gender", accountItemName: "Gender"},
	{jsonName: "birthday", column: "birthday", accountItemName: "Birthday"},
	{jsonName: "education", column: "education", accountItemName: "Education"},
	{jsonName: "cart", column: "cart", accountItemName: "Cart"},
}

var adminUserUpdateFields = []userUpdateField{
	{jsonName: "name", column: "name", accountItemName: "Name"},
	{jsonName: "type", column: "type", accountItemName: "User type"},
	{jsonName: "tag", column: "tag", accountItemName: "Tag"},
	{jsonName: "isVerified", column: "is_verified", accountItemName: "ID verification"},
	{jsonName: "score", column: "score", accountItemName: "Score"},
	{jsonName: "karma", column: "karma", accountItemName: "Karma"},
	{jsonName: "ranking", column: "ranking", accountItemName: "Ranking"},
	{jsonName: "balance", column: "balance", accountItemName: "Balance"},
	{jsonName: "balanceCredit", column: "balance_credit", accountItemName: "Balance credit"},
	{jsonName: "balanceCurrency", column: "balance_currency", accountItemName: "Balance currency"},
	{jsonName: "signupApplication", column: "signup_application", accountItemName: "Signup application"},
	{jsonName: "registerType", column: "register_type", accountItemName: "Register type"},
	{jsonName: "registerSource", column: "register_source", accountItemName: "Register source"},
	{jsonName: "groups", column: "groups", accountItemName: "Groups"},
	{jsonName: "properties", column: "properties", accountItemName: "Properties"},
	{jsonName: "custom", column: "custom", accountItemName: "Properties"},
	{jsonName: "custom2", column: "custom2", accountItemName: "Properties"},
	{jsonName: "custom3", column: "custom3", accountItemName: "Properties"},
	{jsonName: "custom4", column: "custom4", accountItemName: "Properties"},
	{jsonName: "custom5", column: "custom5", accountItemName: "Properties"},
	{jsonName: "custom6", column: "custom6", accountItemName: "Properties"},
	{jsonName: "custom7", column: "custom7", accountItemName: "Properties"},
	{jsonName: "custom8", column: "custom8", accountItemName: "Properties"},
	{jsonName: "custom9", column: "custom9", accountItemName: "Properties"},
	{jsonName: "custom10", column: "custom10", accountItemName: "Properties"},
	{jsonName: "isAdmin", column: "is_admin", accountItemName: "Is admin"},
	{jsonName: "isForbidden", column: "is_forbidden", accountItemName: "Is forbidden"},
	{jsonName: "isDeleted", column: "is_deleted", accountItemName: "Is deleted"},
	{jsonName: "deletedTime", column: "deleted_time", accountItemName: "Is deleted"},
	{jsonName: "needUpdatePassword", column: "need_update_password", accountItemName: "Need update password"},
	{jsonName: "ipWhitelist", column: "ip_whitelist", accountItemName: "IP whitelist"},
}

func allowedUserUpdateFields(isAdmin bool) []userUpdateField {
	fields := append([]userUpdateField(nil), selfUserUpdateFields...)
	if isAdmin {
		fields = append(fields, adminUserUpdateFields...)
	}
	return fields
}

func resolveUserUpdateFields(columns string, isAdmin bool) ([]userUpdateField, bool, error) {
	allowed := allowedUserUpdateFields(isAdmin)
	if columns == "" {
		return allowed, false, nil
	}

	byName := make(map[string]userUpdateField, len(allowed)*2)
	for _, field := range allowed {
		byName[field.jsonName] = field
		byName[field.column] = field
	}

	requested := strings.Split(columns, ",")
	resolved := make([]userUpdateField, 0, len(requested))
	seen := map[string]bool{}
	for _, name := range requested {
		if name == "" || strings.TrimSpace(name) != name {
			return nil, true, fmt.Errorf("invalid user update column %q", name)
		}
		field, ok := byName[name]
		if !ok {
			return nil, true, fmt.Errorf("user update column %q is not allowed", name)
		}
		if seen[field.column] {
			return nil, true, fmt.Errorf("duplicate user update column %q", name)
		}
		seen[field.column] = true
		resolved = append(resolved, field)
	}

	return resolved, true, nil
}

func buildUserUpdateCandidate(oldUser *object.User, requestBody []byte, fields []userUpdateField, explicitColumns bool) (object.User, error) {
	if oldUser == nil {
		return object.User{}, fmt.Errorf("existing user is missing")
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(requestBody, &body); err != nil {
		return object.User{}, err
	}
	if len(body) == 0 {
		return object.User{}, fmt.Errorf("user update body must contain at least one field")
	}

	filtered := make(map[string]json.RawMessage, len(fields))
	for _, field := range fields {
		value, ok := body[field.jsonName]
		if explicitColumns && !ok {
			return object.User{}, fmt.Errorf("request body is missing user update field %q", field.jsonName)
		}
		if ok {
			filtered[field.jsonName] = value
		}
	}
	if len(filtered) == 0 {
		return object.User{}, fmt.Errorf("user update body does not contain an allowed field")
	}

	payload, err := json.Marshal(filtered)
	if err != nil {
		return object.User{}, err
	}
	candidate := *oldUser
	if err = json.Unmarshal(payload, &candidate); err != nil {
		return object.User{}, err
	}
	return candidate, nil
}

func validateUserUpdateFieldPermissions(oldUser, newUser *object.User, fields []userUpdateField, isAdmin bool, lang string) error {
	organization, err := object.GetOrganizationByUser(oldUser)
	if err != nil {
		return err
	}
	if organization == nil {
		return fmt.Errorf("organization does not exist")
	}

	oldJSON, err := json.Marshal(oldUser)
	if err != nil {
		return err
	}
	newJSON, err := json.Marshal(newUser)
	if err != nil {
		return err
	}
	var oldFields map[string]json.RawMessage
	var newFields map[string]json.RawMessage
	if err = json.Unmarshal(oldJSON, &oldFields); err != nil {
		return err
	}
	if err = json.Unmarshal(newJSON, &newFields); err != nil {
		return err
	}

	for _, field := range fields {
		if bytes.Equal(oldFields[field.jsonName], newFields[field.jsonName]) {
			continue
		}
		accountItem := object.GetAccountItemByName(field.accountItemName, organization)
		if accountItem == nil {
			return fmt.Errorf("account item %q is not configured for user updates", field.accountItemName)
		}
		if pass, message := object.CheckAccountItemModifyRule(accountItem, isAdmin, lang); !pass {
			return fmt.Errorf("%s", message)
		}
	}
	return nil
}

func userUpdateColumns(fields []userUpdateField) []string {
	columns := make([]string, 0, len(fields))
	for _, field := range fields {
		columns = append(columns, field.column)
	}
	return columns
}
