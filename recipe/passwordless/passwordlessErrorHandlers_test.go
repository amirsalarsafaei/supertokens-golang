/* Copyright (c) 2021, VRAI Labs and/or its affiliates. All rights reserved.
 *
 * This software is licensed under the Apache License, Version 2.0 (the
 * "License") as published by the Apache Software Foundation.
 *
 * You may not use this file except in compliance with the License. You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package passwordless

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/supertokens/supertokens-golang/recipe/passwordless/errors"
	"github.com/supertokens/supertokens-golang/recipe/passwordless/plessmodels"
	"github.com/supertokens/supertokens-golang/recipe/session"
	"github.com/supertokens/supertokens-golang/recipe/session/sessmodels"
	"github.com/supertokens/supertokens-golang/supertokens"
	"github.com/supertokens/supertokens-golang/test/unittesting"
)

func TestPasswordlessErrorHandlerOverrides(t *testing.T) {
	configValue := supertokens.TypeInput{
		Supertokens: &supertokens.ConnectionInfo{
			ConnectionURI: "http://localhost:8080",
		},
		AppInfo: supertokens.AppInfo{
			APIDomain:     "api.supertokens.io",
			AppName:       "SuperTokens",
			WebsiteDomain: "supertokens.io",
		},
		RecipeList: []supertokens.Recipe{
			Init(plessmodels.TypeInput{
				FlowType: "USER_INPUT_CODE_AND_MAGIC_LINK",
				ContactMethodEmail: plessmodels.ContactMethodEmailConfig{
					Enabled: true,
				},
				ErrorHandlers: &plessmodels.ErrorHandlers{
					OnRestartFlowError: func(message string, req *http.Request, res http.ResponseWriter) error {
						res.Write([]byte("restart flow from errorHandler"))
						return nil
					},
					OnIncorrectUserInputCode: func(message string, failedCodeInputAttemptCount int, maximumCodeInputAttempts int, req *http.Request, res http.ResponseWriter) error {
						res.Write([]byte("incorrect user input code from errorHandler"))
						return nil
					},
					OnExpiredUserInputCodeError: func(message string, failedCodeInputAttemptCount int, maximumCodeInputAttempts int, req *http.Request, res http.ResponseWriter) error {
						res.Write([]byte("expired user input code from errorHandler"))
						return nil
					},
				},
			}),
			session.Init(&sessmodels.TypeInput{
				GetTokenTransferMethod: func(req *http.Request, forCreateNewSession bool, userContext supertokens.UserContext) sessmodels.TokenTransferMethod {
					return sessmodels.CookieTransferMethod
				},
			}),
		},
	}

	BeforeEach()
	unittesting.StartUpST("localhost", "8080")
	defer AfterEach()
	err := supertokens.Init(configValue)
	if err != nil {
		t.Error(err.Error())
	}

	r, _ := http.NewRequest("GET", "", nil)
	rw := httptest.NewRecorder()

	supertokens.ErrorHandler(errors.RestartFlowError{Msg: "test"}, r, rw)
	assert.Equal(t, "restart flow from errorHandler", string(rw.Body.Bytes()))

	rw = httptest.NewRecorder()
	supertokens.ErrorHandler(errors.IncorrectUserInputCodeError{Msg: "test", FailedCodeInputAttemptCount: 1, MaximumCodeInputAttempts: 5}, r, rw)
	assert.Equal(t, "incorrect user input code from errorHandler", string(rw.Body.Bytes()))

	rw = httptest.NewRecorder()
	supertokens.ErrorHandler(errors.ExpiredUserInputCodeError{Msg: "test", FailedCodeInputAttemptCount: 2, MaximumCodeInputAttempts: 5}, r, rw)
	assert.Equal(t, "expired user input code from errorHandler", string(rw.Body.Bytes()))
}

func TestPasswordlessDefaultErrorHandlers(t *testing.T) {
	configValue := supertokens.TypeInput{
		Supertokens: &supertokens.ConnectionInfo{
			ConnectionURI: "http://localhost:8080",
		},
		AppInfo: supertokens.AppInfo{
			APIDomain:     "api.supertokens.io",
			AppName:       "SuperTokens",
			WebsiteDomain: "supertokens.io",
		},
		RecipeList: []supertokens.Recipe{
			Init(plessmodels.TypeInput{
				FlowType: "USER_INPUT_CODE_AND_MAGIC_LINK",
				ContactMethodEmail: plessmodels.ContactMethodEmailConfig{
					Enabled: true,
				},
			}),
			session.Init(&sessmodels.TypeInput{
				GetTokenTransferMethod: func(req *http.Request, forCreateNewSession bool, userContext supertokens.UserContext) sessmodels.TokenTransferMethod {
					return sessmodels.CookieTransferMethod
				},
			}),
		},
	}

	BeforeEach()
	unittesting.StartUpST("localhost", "8080")
	defer AfterEach()
	err := supertokens.Init(configValue)
	if err != nil {
		t.Error(err.Error())
	}

	r, _ := http.NewRequest("GET", "", nil)
	rw := httptest.NewRecorder()

	supertokens.ErrorHandler(errors.RestartFlowError{Msg: "test"}, r, rw)
	body, _ := io.ReadAll(rw.Body)
	assert.Contains(t, string(body), "RESTART_FLOW_ERROR")

	rw = httptest.NewRecorder()
	supertokens.ErrorHandler(errors.IncorrectUserInputCodeError{Msg: "test", FailedCodeInputAttemptCount: 1, MaximumCodeInputAttempts: 5}, r, rw)
	body, _ = io.ReadAll(rw.Body)
	assert.Contains(t, string(body), "INCORRECT_USER_INPUT_CODE_ERROR")
	assert.Contains(t, string(body), "\"failedCodeInputAttemptCount\":1")
	assert.Contains(t, string(body), "\"maximumCodeInputAttempts\":5")

	rw = httptest.NewRecorder()
	supertokens.ErrorHandler(errors.ExpiredUserInputCodeError{Msg: "test", FailedCodeInputAttemptCount: 2, MaximumCodeInputAttempts: 5}, r, rw)
	body, _ = io.ReadAll(rw.Body)
	assert.Contains(t, string(body), "EXPIRED_USER_INPUT_CODE_ERROR")
	assert.Contains(t, string(body), "\"failedCodeInputAttemptCount\":2")
	assert.Contains(t, string(body), "\"maximumCodeInputAttempts\":5")
}
