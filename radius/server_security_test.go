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

package radius

import (
	"testing"

	radiuslib "layeh.com/radius"
)

func TestDisabledRadiusPortNeverStartsListener(t *testing.T) {
	original := listenAndServeRadius
	t.Cleanup(func() { listenAndServeRadius = original })

	for _, port := range []string{"", "0", "-1", "not-a-port", "65536"} {
		t.Run(port, func(t *testing.T) {
			called := false
			listenAndServeRadius = func(_ *radiuslib.PacketServer) error {
				called = true
				return nil
			}
			t.Setenv("radiusServerPort", port)
			StartRadiusServer()
			if called {
				t.Fatalf("RADIUS listener started for disabled/invalid port %q", port)
			}
		})
	}
}

func TestEnabledRadiusPortUsesExactListenerAddress(t *testing.T) {
	original := listenAndServeRadius
	t.Cleanup(func() { listenAndServeRadius = original })
	t.Setenv("radiusServerPort", "18120")

	called := false
	listenAndServeRadius = func(server *radiuslib.PacketServer) error {
		called = true
		if server.Addr != "0.0.0.0:18120" {
			t.Fatalf("RADIUS address = %q", server.Addr)
		}
		return nil
	}
	StartRadiusServer()
	if !called {
		t.Fatal("valid RADIUS port did not reach listener")
	}
}
