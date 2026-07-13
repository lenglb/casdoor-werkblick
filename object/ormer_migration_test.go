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

import "testing"

func TestPostgresFloatColumnMigrationTypePolicy(t *testing.T) {
	tests := []struct {
		dataType string
		want     bool
		wantErr  bool
	}{
		{dataType: "double precision", want: false},
		{dataType: "smallint", want: true},
		{dataType: "integer", want: true},
		{dataType: "bigint", want: true},
		{dataType: "", wantErr: true},
		{dataType: "numeric", wantErr: true},
		{dataType: "text", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.dataType, func(t *testing.T) {
			got, err := postgresFloatColumnNeedsMigration(test.dataType)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("needs migration = %v, want %v", got, test.want)
			}
		})
	}
}
