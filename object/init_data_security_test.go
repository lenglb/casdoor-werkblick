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
	"path/filepath"
	"testing"
)

func TestInitFromFileRequiredRejectsMissingInput(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing-init-data.json")} {
		t.Run(path, func(t *testing.T) {
			t.Setenv("initDataFile", path)
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatalf("missing initDataFile %q did not fail closed", path)
				}
			}()
			InitFromFileRequired()
		})
	}
}
