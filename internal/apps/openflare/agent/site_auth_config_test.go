// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

func TestRequiresSiteAuth(t *testing.T) {
	if got, err := requiresSiteAuth(`{"routes":[{"oidc_auth_source_id":1}]}`); err != nil || !got {
		t.Errorf("requiresSiteAuth(OIDC) = %v, %v, want true", got, err)
	}
	if got, err := requiresSiteAuth(`{"routes":[{"basic_auth_enabled":true}]}`); err != nil || got {
		t.Errorf("requiresSiteAuth(Basic) = %v, %v, want false", got, err)
	}
	if _, err := requiresSiteAuth(`invalid`); err == nil {
		t.Error("requiresSiteAuth(invalid JSON) accepted, want rejected")
	}
}
