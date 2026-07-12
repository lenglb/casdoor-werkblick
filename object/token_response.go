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

// MaskTokenForResponse returns an alias-free administrative view of a token.
// Authorization codes, bearer credentials, lookup hashes, and refresh-family
// identifiers are verification material, not management metadata, and must not
// be exposed through list/detail APIs even to an administrator's browser.
func MaskTokenForResponse(token *Token) *Token {
	if token == nil {
		return nil
	}

	masked := *token
	masked.Code = ""
	masked.AccessToken = ""
	masked.RefreshToken = ""
	masked.AccessTokenHash = ""
	masked.RefreshTokenHash = ""
	masked.RefreshTokenFamily = ""
	masked.AuthenticationMethods = append([]string(nil), token.AuthenticationMethods...)
	return &masked
}

func MaskTokensForResponse(tokens []*Token) []*Token {
	if tokens == nil {
		return nil
	}
	masked := make([]*Token, len(tokens))
	for i, token := range tokens {
		masked[i] = MaskTokenForResponse(token)
	}
	return masked
}
