// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

type Token struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	Application  string `xorm:"varchar(100)" json:"application"`
	Organization string `xorm:"varchar(100)" json:"organization"`
	User         string `xorm:"varchar(100)" json:"user"`
	// Subject is the immutable user/application ID bound to this grant. Owner,
	// organization and user names are mutable and therefore are not sufficient
	// to prevent a deleted account name from being reused.
	Subject string `xorm:"varchar(100)" json:"subject"`

	Code                   string   `xorm:"varchar(100) index" json:"code"`
	AccessToken            string   `xorm:"mediumtext" json:"accessToken"`
	RefreshToken           string   `xorm:"mediumtext" json:"refreshToken"`
	AccessTokenHash        string   `xorm:"varchar(100) index" json:"accessTokenHash"`
	RefreshTokenHash       string   `xorm:"varchar(100) index" json:"refreshTokenHash"`
	RefreshTokenFamily     string   `xorm:"varchar(255) index" json:"refreshTokenFamily"`
	RefreshTokenConsumed   bool     `xorm:"index" json:"refreshTokenConsumed"`
	ExpiresIn              int      `json:"expiresIn"`
	Scope                  string   `xorm:"varchar(300)" json:"scope"`
	Nonce                  string   `xorm:"varchar(255)" json:"nonce"`
	TokenType              string   `xorm:"varchar(100)" json:"tokenType"`
	GrantType              string   `xorm:"varchar(100)" json:"grantType"`
	CodeChallenge          string   `xorm:"varchar(100)" json:"codeChallenge"`
	RedirectUri            string   `xorm:"varchar(500)" json:"redirectUri"`
	CodeIsUsed             bool     `json:"codeIsUsed"`
	CodeExpireIn           int64    `json:"codeExpireIn"`
	AuthTime               int64    `json:"authTime"`
	AuthenticationMethods  []string `xorm:"mediumtext" json:"authenticationMethods"`
	AuthenticationProvider string   `xorm:"varchar(100)" json:"authenticationProvider"`
	Resource               string   `xorm:"varchar(255)" json:"resource"`           // RFC 8707 Resource Indicator
	DPoPJkt                string   `xorm:"varchar(255) 'dpop_jkt'" json:"dPoPJkt"` // RFC 9449 DPoP JWK thumbprint binding
}

// SetAuthenticationContext binds trusted authentication evidence to a token.
// The subject is represented by the token's organization/user columns and must
// match the supplied context before any evidence is persisted.
func (token *Token) SetAuthenticationContext(authenticationContext AuthenticationContext) error {
	preserved, err := PreserveAuthenticationContext(authenticationContext)
	if err != nil {
		return err
	}

	expectedSubject := util.GetId(token.Organization, token.User)
	if preserved.Subject != expectedSubject {
		return fmt.Errorf("authentication context subject %q does not match token subject %q", preserved.Subject, expectedSubject)
	}

	token.AuthTime = preserved.AuthTime
	token.AuthenticationMethods = preserved.Amr
	token.AuthenticationProvider = preserved.Provider
	return nil
}

// GetAuthenticationContext reconstructs a deep, validated copy of the
// authentication evidence persisted with a token.
func (token *Token) GetAuthenticationContext() (AuthenticationContext, error) {
	return PreserveAuthenticationContext(AuthenticationContext{
		Subject:  util.GetId(token.Organization, token.User),
		AuthTime: token.AuthTime,
		Amr:      token.AuthenticationMethods,
		Provider: token.AuthenticationProvider,
	})
}

func GetTokenCount(owner, organization, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Token{Organization: organization})
}

func GetTokens(owner string, organization string) ([]*Token, error) {
	tokens := []*Token{}
	err := ormer.Engine.Desc("created_time").Find(&tokens, &Token{Owner: owner, Organization: organization})
	return tokens, err
}

func GetPaginationTokens(owner, organization string, offset, limit int, field, value, sortField, sortOrder string) ([]*Token, error) {
	tokens := []*Token{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&tokens, &Token{Organization: organization})
	return tokens, err
}

func getToken(owner string, name string) (*Token, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	token := Token{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&token)
	if err != nil {
		return nil, err
	}

	if existed {
		return &token, nil
	}

	return nil, nil
}

func getTokenByCode(code string) (*Token, error) {
	token := Token{Code: code}
	existed, err := ormer.Engine.Get(&token)
	if err != nil {
		return nil, err
	}

	if existed {
		return &token, nil
	}

	return nil, nil
}

func GetTokenByAccessToken(accessToken string) (*Token, error) {
	token := Token{AccessTokenHash: getTokenHash(accessToken)}
	existed, err := ormer.Engine.Get(&token)
	if err != nil {
		return nil, err
	}

	if !existed {
		return nil, nil
	}
	return &token, nil
}

func GetTokenByRefreshToken(refreshToken string) (*Token, error) {
	token := Token{RefreshTokenHash: getTokenHash(refreshToken)}
	existed, err := ormer.Engine.Get(&token)
	if err != nil {
		return nil, err
	}

	if !existed {
		return nil, nil
	}
	return &token, nil
}

func GetTokenByTokenValue(tokenValue, tokenTypeHint string) (*Token, error) {
	switch tokenTypeHint {
	case "access_token", "access-token":
		token, err := GetTokenByAccessToken(tokenValue)
		if err != nil {
			return nil, err
		}
		if token != nil {
			return token, nil
		}
	case "refresh_token", "refresh-token":
		token, err := GetTokenByRefreshToken(tokenValue)
		if err != nil {
			return nil, err
		}
		if token != nil {
			return token, nil
		}
	}

	return nil, nil
}

// consumeAuthorizationCode marks a validated authorization code as used exactly
// once. The conditional update is the replay boundary: concurrent exchanges for
// the same code can no longer all pass a separate read-before-write check.
//
// When a DPoP proof was validated before the exchange, its thumbprint and token
// type are persisted in the same database operation. This avoids consuming a
// code before its proof has been checked or leaving a consumed code without the
// corresponding binding.
type authorizationCodeTokenReplacement struct {
	AccessToken  string
	RefreshToken string
}

func consumeAuthorizationCode(token *Token, dpopJkt string, replacement *authorizationCodeTokenReplacement) (bool, error) {
	update := &Token{CodeIsUsed: true}
	columns := []string{"code_is_used"}
	if dpopJkt != "" {
		update.TokenType = "DPoP"
		update.DPoPJkt = dpopJkt
		columns = append(columns, "token_type", "dpop_jkt")
	}
	if replacement != nil {
		update.AccessToken = replacement.AccessToken
		update.RefreshToken = replacement.RefreshToken
		update.AccessTokenHash = getTokenHash(replacement.AccessToken)
		update.RefreshTokenHash = getTokenHash(replacement.RefreshToken)
		columns = append(columns, "access_token", "refresh_token", "access_token_hash", "refresh_token_hash")
	}

	affected, err := ormer.Engine.
		ID(core.PK{token.Owner, token.Name}).
		Where("code = ? AND code_is_used = ?", token.Code, false).
		Cols(columns...).
		Update(update)
	if err != nil {
		return false, err
	}

	return affected == 1, nil
}

// rotateRefreshToken consumes an existing refresh-token record and inserts its
// successor in one transaction. The consumed row is retained as a tombstone so
// later reuse can revoke the complete token family. A failed insert rolls the
// consume operation back and keeps the old token usable.
func rotateRefreshToken(oldToken *Token, newToken *Token) (bool, error) {
	family := oldToken.RefreshTokenFamily
	if family == "" {
		family = oldToken.GetId()
	}
	newToken.RefreshTokenFamily = family
	newToken.RefreshTokenConsumed = false
	newToken.popularHashes()

	session := ormer.Engine.NewSession()
	defer session.Close()

	if err := session.Begin(); err != nil {
		return false, err
	}
	rollback := func(err error) (bool, error) {
		if rollbackErr := session.Rollback(); rollbackErr != nil {
			err = errors.Join(err, rollbackErr)
		}
		return false, err
	}

	consumed := &Token{
		ExpiresIn:            0,
		RefreshTokenConsumed: true,
		RefreshTokenFamily:   family,
	}
	affected, err := session.
		ID(core.PK{oldToken.Owner, oldToken.Name}).
		Where(
			"organization = ? AND application = ? AND refresh_token_hash = ? AND refresh_token_consumed = ?",
			oldToken.Organization,
			oldToken.Application,
			oldToken.RefreshTokenHash,
			false,
		).
		Cols("expires_in", "refresh_token_consumed", "refresh_token_family").
		Update(consumed)
	if err != nil {
		return rollback(err)
	}
	if affected != 1 {
		return rollback(nil)
	}

	affected, err = session.Insert(newToken)
	if err != nil {
		return rollback(err)
	}
	if affected != 1 {
		return rollback(fmt.Errorf("failed to insert rotated refresh token"))
	}

	if err = session.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func GetToken(id string) (*Token, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return nil, err
	}
	return getToken(owner, name)
}

func (token *Token) GetId() string {
	return fmt.Sprintf("%s/%s", token.Owner, token.Name)
}

func getTokenHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	res := hex.EncodeToString(hash[:])
	if len(res) > 64 {
		return res[:64]
	}
	return res
}

func (token *Token) popularHashes() {
	if token.AccessTokenHash == "" && token.AccessToken != "" {
		token.AccessTokenHash = getTokenHash(token.AccessToken)
	}
	if token.RefreshTokenHash == "" && token.RefreshToken != "" {
		token.RefreshTokenHash = getTokenHash(token.RefreshToken)
	}
	if token.RefreshToken != "" && token.RefreshTokenFamily == "" {
		token.RefreshTokenFamily = token.GetId()
	}
}

func revokeRefreshTokenFamily(token *Token) error {
	if token == nil || token.RefreshTokenFamily == "" {
		return nil
	}
	_, err := ormer.Engine.
		Where("owner = ? AND application = ? AND refresh_token_family = ?", token.Owner, token.Application, token.RefreshTokenFamily).
		Cols("expires_in").
		Update(&Token{ExpiresIn: 0})
	return err
}

func UpdateToken(id string, token *Token, isGlobalAdmin bool) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromIdWithError(id)
	if err != nil {
		return false, err
	}
	if t, err := getToken(owner, name); err != nil {
		return false, err
	} else if t == nil {
		return false, nil
	} else if !isGlobalAdmin && t.Organization != token.Organization {
		return false, nil
	} else if token.ExpiresIn < 0 || token.ExpiresIn > t.ExpiresIn {
		return false, fmt.Errorf("token expiration can only be shortened")
	}

	// Administrative token management is revocation-only. Signed claims and
	// bearer credentials are immutable; allowing a browser to rewrite them would
	// create an unsigned credential-injection path through introspection.
	affected, err := ormer.Engine.ID(core.PK{owner, name}).Cols("expires_in").Update(&Token{ExpiresIn: token.ExpiresIn})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func AddToken(token *Token) (bool, error) {
	token.popularHashes()

	affected, err := ormer.Engine.Insert(token)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteToken(token *Token) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{token.Owner, token.Name}).Where("organization = ?", token.Organization).Delete(&Token{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func GetActiveTokensByUser(organization, username string) ([]*Token, error) {
	tokens := []*Token{}
	err := ormer.Engine.Where("organization = ? and user = ? and expires_in > 0", organization, username).Find(&tokens)
	return tokens, err
}

func ExpireTokenByUser(owner, username string) (bool, error) {
	affected, err := ormer.Engine.Where("organization = ? and user = ?", owner, username).Cols("expires_in").Update(&Token{ExpiresIn: 0})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

// updateTokenDPoP updates the token_type and dpop_jkt columns for DPoP binding (RFC 9449).
func updateTokenDPoP(token *Token) error {
	_, err := ormer.Engine.ID(core.PK{token.Owner, token.Name}).Cols("token_type", "dpop_jkt").Update(token)
	return err
}

// replaceIssuedTokenWithDPoP atomically replaces the signed credentials of a
// freshly issued token with credentials containing the matching cnf claim. A
// database-only DPoP marker is insufficient because resource servers validate
// the signed JWT, not Casdoor's token row.
func replaceIssuedTokenWithDPoP(token *Token, accessToken string, refreshToken string, dpopJkt string) (bool, error) {
	update := &Token{
		AccessToken:      accessToken,
		AccessTokenHash:  getTokenHash(accessToken),
		RefreshToken:     refreshToken,
		RefreshTokenHash: getTokenHash(refreshToken),
		TokenType:        "DPoP",
		DPoPJkt:          dpopJkt,
	}
	columns := []string{"access_token", "access_token_hash", "token_type", "dpop_jkt"}
	if token.RefreshToken != "" {
		columns = append(columns, "refresh_token", "refresh_token_hash")
	} else {
		update.RefreshToken = ""
		update.RefreshTokenHash = ""
	}

	affected, err := ormer.Engine.
		ID(core.PK{token.Owner, token.Name}).
		Where("access_token_hash = ?", token.AccessTokenHash).
		Cols(columns...).
		Update(update)
	return affected == 1, err
}
