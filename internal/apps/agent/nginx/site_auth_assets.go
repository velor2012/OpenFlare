// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package nginx

import (
	_ "embed"

	"github.com/Rain-kl/Wavelet/internal/apps/agent/protocol"
)

//go:embed site_auth_runtime.lua
var siteAuthRuntimeLua string

// ManagedSiteAuthLuaFiles returns the site authentication runtime.
func ManagedSiteAuthLuaFiles() []protocol.SupportFile {
	return []protocol.SupportFile{{Path: "site_auth/runtime.lua", Content: siteAuthRuntimeLua}}
}
