// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

// Package root registers custom business routes and frontend serving.
package root

import (
	"github.com/Rain-kl/Wavelet/internal/apps/openflare/site_auth"
	"github.com/gin-gonic/gin"
)

// RegisterCustomRootRoutes registers custom business routes that belong to the root path.
func RegisterCustomRootRoutes(r *gin.Engine) {
	// Public OIDC browser/node endpoints are business-specific and deliberately
	// do not require a platform login or modify the framework OAuth router.
	auth := r.Group(site_auth.Prefix)
	auth.GET("login", site_auth.LoginHandler)
	auth.GET("callback", site_auth.CallbackHandler)
	auth.POST("exchange", site_auth.ExchangeHandler)
	auth.POST("check", site_auth.CheckHandler)
}
