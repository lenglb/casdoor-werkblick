// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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

package radius

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

var StateMap map[string]AccessStateContent
var stateMapMutex sync.Mutex

const StateExpiredTime = time.Second * 120
const MaxPendingAccessStates = 4096

var listenAndServeRadius = func(server *radius.PacketServer) error {
	return server.ListenAndServe()
}

type AccessStateContent struct {
	ExpiredAt time.Time
	Owner     string
	User      string
	Subject   string
}

type accessRequestDependencies struct {
	checkUserPassword func(organization string, username string, password string, lang string) (*object.User, error)
	getUser           func(id string) (*object.User, error)
	now               func() time.Time
}

var defaultAccessRequestDependencies = accessRequestDependencies{
	checkUserPassword: func(organization string, username string, password string, lang string) (*object.User, error) {
		return object.CheckUserPassword(organization, username, password, lang)
	},
	getUser: object.GetUser,
	now:     time.Now,
}

func StartRadiusServer() {
	if conf.GetConfigString("radiusServerEnabled") != "true" {
		log.Printf("RADIUS server disabled: radiusServerEnabled must be explicitly true")
		return
	}
	port, err := strconv.Atoi(conf.GetConfigString("radiusServerPort"))
	if err != nil || port <= 0 || port > 65535 {
		log.Printf("RADIUS server disabled: radiusServerPort must be between 1 and 65535")
		return
	}
	secret := conf.GetConfigString("radiusSecret")
	if len(secret) < 16 || secret == "secret" {
		log.Printf("RADIUS server disabled: radiusSecret must be non-default and at least 16 characters")
		return
	}
	server := radius.PacketServer{
		Addr:         fmt.Sprintf("0.0.0.0:%d", port),
		Handler:      radius.HandlerFunc(handlerRadius),
		SecretSource: radius.StaticSecretSource([]byte(secret)),
	}
	log.Printf("Starting Radius server on %s", server.Addr)
	if err = listenAndServeRadius(&server); err != nil {
		log.Printf("StartRadiusServer() failed, err = %v", err)
	}
}

func issueAccessState(owner string, user string, subject string, now time.Time) (string, error) {
	if subject == "" {
		return "", fmt.Errorf("RADIUS MFA challenge requires an immutable user subject")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(random)

	stateMapMutex.Lock()
	defer stateMapMutex.Unlock()
	if StateMap == nil {
		StateMap = map[string]AccessStateContent{}
	}
	for candidate, content := range StateMap {
		if !content.ExpiredAt.After(now) {
			delete(StateMap, candidate)
		}
	}
	if len(StateMap) >= MaxPendingAccessStates {
		return "", fmt.Errorf("too many pending RADIUS MFA challenges")
	}
	StateMap[state] = AccessStateContent{
		ExpiredAt: now.Add(StateExpiredTime),
		Owner:     owner,
		User:      user,
		Subject:   subject,
	}
	return state, nil
}

func consumeAccessState(state string, owner string, user string, now time.Time) (string, bool) {
	if state == "" {
		return "", false
	}
	stateMapMutex.Lock()
	defer stateMapMutex.Unlock()
	stateContent, ok := StateMap[state]
	if !ok {
		return "", false
	}
	// Every presented state is consumed, including expired or cross-user
	// attempts, so a captured value can never be replayed after probing.
	delete(StateMap, state)
	valid := stateContent.ExpiredAt.After(now) &&
		stateContent.Owner == owner &&
		stateContent.User == user &&
		stateContent.Subject != ""
	if !valid {
		return "", false
	}
	return stateContent.Subject, true
}

func handlerRadius(w radius.ResponseWriter, r *radius.Request) {
	switch r.Code {
	case radius.CodeAccessRequest:
		handleAccessRequest(w, r)
	case radius.CodeAccountingRequest:
		handleAccountingRequest(w, r)
	default:
		log.Printf("radius message, code = %d", r.Code)
	}
}

func handleAccessRequest(w radius.ResponseWriter, r *radius.Request) {
	handleAccessRequestWithDependencies(w, r, defaultAccessRequestDependencies)
}

func handleAccessRequestWithDependencies(w radius.ResponseWriter, r *radius.Request, dependencies accessRequestDependencies) {
	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)
	organization := rfc2865.Class_GetString(r.Packet)
	state := rfc2865.State_GetString(r.Packet)
	log.Printf("handleAccessRequest() username=%v, org=%v", username, organization)

	if organization == "" {
		organization = conf.GetConfigString("radiusDefaultOrganization")
		if organization == "" {
			organization = "built-in"
		}
	}

	var user *object.User
	var err error
	stateSubject := ""

	if state == "" {
		user, err = dependencies.checkUserPassword(organization, username, password, "en")
	} else {
		var stateValid bool
		stateSubject, stateValid = consumeAccessState(state, organization, username, dependencies.now())
		if !stateValid {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		user, err = dependencies.getUser(fmt.Sprintf("%s/%s", organization, username))
	}

	if err != nil || user == nil {
		w.Write(r.Response(radius.CodeAccessReject))
		return
	}
	if state != "" {
		if user.Id == "" || user.Id != stateSubject || user.IsDeleted || user.IsForbidden || !user.IsMfaEnabled() {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		mfaProp := user.GetMfaProps(object.TotpType, false)
		if mfaProp == nil || !mfaProp.Enabled || mfaProp.Secret == "" {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		mfaUtil := object.GetMfaUtil(mfaProp.MfaType, mfaProp)
		if mfaUtil == nil || mfaUtil.Verify(password) != nil {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
		w.Write(r.Response(radius.CodeAccessAccept))
		return
	}

	if user.IsMfaEnabled() {
		mfaProp := user.GetMfaProps(object.TotpType, false)
		if mfaProp == nil || !mfaProp.Enabled || mfaProp.Secret == "" {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		responseState, stateErr := issueAccessState(organization, username, user.Id, dependencies.now())
		if stateErr != nil {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		challenge := r.Response(radius.CodeAccessChallenge)
		err = rfc2865.State_Set(challenge, []byte(responseState))
		if err != nil {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		err = rfc2865.ReplyMessage_Set(challenge, []byte("please enter OTP"))
		if err != nil {
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		w.Write(challenge)
		return
	}

	w.Write(r.Response(radius.CodeAccessAccept))
}

func handleAccountingRequest(w radius.ResponseWriter, r *radius.Request) {
	statusType := rfc2866.AcctStatusType_Get(r.Packet)
	username := rfc2865.UserName_GetString(r.Packet)
	organization := rfc2865.Class_GetString(r.Packet)

	if strings.Contains(username, "/") {
		var err error
		organization, username, err = util.GetOwnerAndNameFromIdWithError(username)
		if err != nil {
			log.Printf("handleAccountingRequest() failed to parse username, err = %v", err)
			w.Write(r.Response(radius.CodeAccessReject))
			return
		}
	}

	log.Printf("handleAccountingRequest() username=%v, org=%v, statusType=%v", username, organization, statusType)
	w.Write(r.Response(radius.CodeAccountingResponse))
	var err error
	defer func() {
		if err != nil {
			log.Printf("handleAccountingRequest() failed, err = %v", err)
		}
	}()
	switch statusType {
	case rfc2866.AcctStatusType_Value_Start:
		// Start an accounting session
		ra := GetAccountingFromRequest(r)
		err = object.AddRadiusAccounting(ra)
	case rfc2866.AcctStatusType_Value_InterimUpdate, rfc2866.AcctStatusType_Value_Stop:
		// Interim update to an accounting session | Stop an accounting session
		var (
			newRa = GetAccountingFromRequest(r)
			oldRa *object.RadiusAccounting
		)
		oldRa, err = object.GetRadiusAccountingBySessionId(newRa.AcctSessionId)
		if err != nil {
			return
		}
		if oldRa == nil {
			if err = object.AddRadiusAccounting(newRa); err != nil {
				return
			}
		}
		stop := statusType == rfc2866.AcctStatusType_Value_Stop
		err = object.InterimUpdateRadiusAccounting(oldRa, newRa, stop)
	case rfc2866.AcctStatusType_Value_AccountingOn, rfc2866.AcctStatusType_Value_AccountingOff:
		// By default, no Accounting-On or Accounting-Off messages are sent (no acct-on-off).
	default:
		err = fmt.Errorf("unsupport statusType = %v", statusType)
	}
}
