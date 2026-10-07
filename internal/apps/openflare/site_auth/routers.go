// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package site_auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/Rain-kl/Wavelet/internal/repository"
	"github.com/Rain-kl/Wavelet/internal/shared/response"
	"github.com/Rain-kl/Wavelet/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func abort(c *gin.Context, err error) {
	var apiError *response.APIError
	switch {
	case errors.As(err, &apiError):
		response.AbortWithError(c, apiError.Code, apiError.Msg)
	case errors.Is(err, redis.Nil), errors.Is(err, gorm.ErrRecordNotFound):
		response.AbortUnauthorized(c, errInvalid)
	default:
		// Error text from OAuth servers can contain tokens; log the type only.
		logger.ErrorF(c.Request.Context(), "site authentication failed: error_type=%T", err)
		response.AbortInternal(c, errUnavailable)
	}
}

func privateResponse(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
}

func stateCookie(state, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: "__Host-openflare_oidc_" + state, Value: value, Path: "/", MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

// LoginHandler starts site OIDC authentication without logging into the platform.
// @Summary 发起站点 OIDC 认证
// @Tags openflare-site-auth
// @Param route_id query int true "代理规则 ID"
// @Param return_url query string true "HTTPS 站点返回地址"
// @Param binding query string true "站点浏览器挑战 SHA-256"
// @Success 302 {string} string "OIDC 授权跳转"
// @Failure 400 {object} response.Any
// @Failure 401 {object} response.Any
// @Failure 403 {object} response.Any
// @Failure 429 {object} response.Any
// @Failure 500 {object} response.Any
// @Router /api/v1/site-auth/login [get]
func LoginHandler(c *gin.Context) {
	privateResponse(c)
	allowed, err := repository.AllowSiteAuthLogin(c.Request.Context(), c.ClientIP())
	if err != nil {
		abort(c, err)
		return
	}
	if !allowed {
		response.AbortTooManyRequests(c, "站点登录请求过于频繁，请稍后重试")
		return
	}
	id, err := parseRouteID(c.Query("route_id"))
	if err != nil {
		response.AbortBadRequest(c, errInvalid)
		return
	}
	browser := oauth2.GenerateVerifier()
	location, state, err := beginLogin(c.Request.Context(), id, c.Query("return_url"), c.Query("binding"), browser)
	if err != nil {
		abort(c, err)
		return
	}
	http.SetCookie(c.Writer, stateCookie(state, browser, int(stateTTL/time.Second)))
	c.Redirect(http.StatusFound, location)
}

// CallbackHandler verifies OIDC and returns a one-use site ticket.
// @Summary 完成站点 OIDC 回调
// @Tags openflare-site-auth
// @Param state query string true "OIDC state"
// @Param code query string true "授权码"
// @Success 302 {string} string "返回站点"
// @Failure 400 {object} response.Any
// @Failure 401 {object} response.Any
// @Failure 403 {object} response.Any
// @Failure 500 {object} response.Any
// @Router /api/v1/site-auth/callback [get]
func CallbackHandler(c *gin.Context) {
	privateResponse(c)
	state := c.Query("state")
	if !validToken(state) {
		response.AbortBadRequest(c, errInvalid)
		return
	}
	cookie := stateCookie(state, "", -1)
	browser, err := c.Cookie(cookie.Name)
	if err != nil || c.Query("error") != "" {
		response.AbortBadRequest(c, errInvalid)
		return
	}
	http.SetCookie(c.Writer, cookie)
	location, err := finishLogin(c.Request.Context(), state, c.Query("code"), browser)
	if err != nil {
		abort(c, err)
		return
	}
	c.Redirect(http.StatusFound, location)
}

// ExchangeHandler consumes a browser-bound ticket and creates a site session.
// @Summary 兑换站点认证凭证
// @Tags openflare-site-auth
// @Accept json
// @Produce json
// @Param body body site_auth.SessionInput true "一次性凭证与浏览器绑定"
// @Success 200 {object} response.Any{data=site_auth.SessionResult}
// @Failure 400 {object} response.Any
// @Failure 401 {object} response.Any
// @Failure 403 {object} response.Any
// @Failure 500 {object} response.Any
// @Router /api/v1/site-auth/exchange [post]
func ExchangeHandler(c *gin.Context) {
	privateResponse(c)
	var input SessionInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.AbortBadRequest(c, errInvalid)
		return
	}
	result, err := exchangeTicket(c.Request.Context(), input)
	if err != nil {
		abort(c, err)
		return
	}
	c.JSON(http.StatusOK, response.OK(result))
}

// CheckHandler validates a site session and the current source/route status.
// @Summary 校验站点认证会话
// @Tags openflare-site-auth
// @Accept json
// @Produce json
// @Param body body site_auth.SessionInput true "站点会话"
// @Success 200 {object} response.Any
// @Failure 400 {object} response.Any
// @Failure 401 {object} response.Any
// @Failure 403 {object} response.Any
// @Failure 500 {object} response.Any
// @Router /api/v1/site-auth/check [post]
func CheckHandler(c *gin.Context) {
	privateResponse(c)
	var input SessionInput
	if err := c.ShouldBindJSON(&input); err != nil {
		response.AbortBadRequest(c, errInvalid)
		return
	}
	if err := checkSession(c.Request.Context(), input); err != nil {
		abort(c, err)
		return
	}
	c.JSON(http.StatusOK, response.OKNil())
}
