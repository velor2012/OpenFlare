// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

// Package site_auth protects proxy sites using centrally managed OIDC sources.
package site_auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Rain-kl/Wavelet/internal/apps/oauth"
	"github.com/Rain-kl/Wavelet/internal/model"
	"github.com/Rain-kl/Wavelet/internal/repository"
	"github.com/Rain-kl/Wavelet/internal/shared/response"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// Prefix is the control-plane endpoint.
	Prefix = "/api/v1/site-auth/"
	// SitePrefix is reserved on protected sites.
	SitePrefix         = "/openflare/site-auth/"
	stateTTL           = 10 * time.Minute
	ticketTTL          = time.Minute
	sessionTTL         = 8 * time.Hour
	maxReturnURLLength = 4096
	hashLength         = 64
	tokenLength        = 43
	oidcRequestTimeout = 10 * time.Second
	errInvalid         = "站点认证请求无效或已过期，请重新登录"
	errUnavailable     = "站点认证暂时不可用"
	errDisabled        = "站点或 OIDC 认证源未启用"
)

var oidcHTTPClient = &http.Client{Timeout: oidcRequestTimeout}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func validToken(value string) bool {
	if len(value) != tokenLength {
		return false
	}
	for _, char := range value {
		switch {
		case char >= 'A' && char <= 'Z', char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '_', char == '-':
		default:
			return false
		}
	}
	return true
}

// ControlURL requires a fixed HTTPS origin so callbacks cannot be influenced by Host headers.
func ControlURL(ctx context.Context) (string, error) {
	config, err := repository.GetSystemConfigByKey(ctx, model.ConfigKeyServerAddress)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(strings.TrimRight(config.Value, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return "", response.NewError(http.StatusBadRequest, "OIDC 站点认证需要将系统服务器地址配置为 HTTPS 域名")
	}
	return parsed.String(), nil
}

func loadSource(ctx context.Context, routeID uint) (*model.AuthSource, error) {
	// ponytail: per-request DB reads make revocation immediate; add an
	// invalidation-backed cache only if protected-site traffic warrants it.
	route, err := repository.GetProxyRouteByID(ctx, routeID)
	if err != nil {
		return nil, err
	}
	if !route.Enabled || !route.EnableHTTPS || !route.RedirectHTTP || route.OIDCAuthSourceID == nil || route.BasicAuthEnabled {
		return nil, response.NewError(http.StatusForbidden, errDisabled)
	}
	source, err := repository.GetAuthSourceByID(ctx, *route.OIDCAuthSourceID)
	if err != nil {
		return nil, err
	}
	if !source.IsActive || source.Type != model.AuthSourceTypeOIDC {
		return nil, response.NewError(http.StatusForbidden, errDisabled)
	}
	return source, nil
}

func validateReturnURL(ctx context.Context, routeID uint, raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if len(raw) > maxReturnURLLength || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Port() != "" && parsed.Port() != "443") || strings.ContainsAny(raw, "\r\n\\") || strings.ContainsAny(parsed.Path, "\r\n\\") || strings.HasPrefix(parsed.Path, SitePrefix) {
		return nil, response.NewError(http.StatusBadRequest, errInvalid)
	}
	domains, err := repository.ListZoneDomainsByRouteID(ctx, routeID)
	if err != nil {
		return nil, err
	}
	for _, domain := range domains {
		if matchesDomain(parsed.Hostname(), domain.Domain) {
			return parsed, nil
		}
	}
	return nil, response.NewError(http.StatusBadRequest, errInvalid)
}

func matchesDomain(host, domain string) bool {
	host, domain = strings.ToLower(host), strings.ToLower(domain)
	if strings.HasPrefix(domain, "*.") {
		return strings.HasSuffix(host, domain[1:]) && len(host) > len(domain)-1
	}
	return host == domain
}

func beginLogin(ctx context.Context, routeID uint, returnURL, binding, browser string) (string, string, error) {
	ctx = oidc.ClientContext(ctx, oidcHTTPClient)
	if decoded, err := hex.DecodeString(binding); err != nil || len(decoded)*2 != hashLength {
		return "", "", response.NewError(http.StatusBadRequest, errInvalid)
	}
	source, err := loadSource(ctx, routeID)
	if err != nil {
		return "", "", err
	}
	if _, err := validateReturnURL(ctx, routeID, returnURL); err != nil {
		return "", "", err
	}
	control, err := ControlURL(ctx)
	if err != nil {
		return "", "", err
	}
	client, _, err := oauth.BuildOAuthConfig(ctx, source, control+Prefix+"callback")
	if err != nil {
		return "", "", err
	}
	state, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	record := model.SiteAuthRecord{RouteID: routeID, SourceID: source.ID, SourceVersion: source.UpdatedAt.UTC().Format(time.RFC3339Nano), ReturnURL: returnURL, Binding: binding, BrowserHash: hash(browser), Verifier: verifier}
	if err := repository.SaveSiteAuthRecord(ctx, "state", state, record, stateTTL); err != nil {
		return "", "", err
	}
	return client.AuthCodeURL(state, oidc.Nonce(state), oauth2.S256ChallengeOption(verifier)), state, nil
}

func finishLogin(ctx context.Context, state, code, browser string) (string, error) {
	ctx = oidc.ClientContext(ctx, oidcHTTPClient)
	if !validToken(state) || code == "" || !validToken(browser) {
		return "", response.NewError(http.StatusBadRequest, errInvalid)
	}
	// Check browser binding before consuming state: another browser must not burn it.
	record, err := repository.GetSiteAuthRecord(ctx, "state", state, false)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare([]byte(record.BrowserHash), []byte(hash(browser))) != 1 {
		return "", response.NewError(http.StatusBadRequest, errInvalid)
	}
	record, err = repository.GetSiteAuthRecord(ctx, "state", state, true)
	if err != nil {
		return "", err
	}
	source, target, err := validateRecord(ctx, record, record.RouteID, "")
	if err != nil {
		return "", err
	}
	control, err := ControlURL(ctx)
	if err != nil {
		return "", err
	}
	client, verifier, err := oauth.BuildOAuthConfig(ctx, source, control+Prefix+"callback")
	if err != nil {
		return "", err
	}
	token, err := client.Exchange(ctx, code, oauth2.VerifierOption(record.Verifier))
	if err != nil {
		return "", err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", response.NewError(http.StatusBadRequest, errInvalid)
	}
	idToken, err := verifier.Verify(ctx, raw)
	if err != nil || idToken.Nonce != state || idToken.Subject == "" {
		return "", response.NewError(http.StatusBadRequest, errInvalid)
	}
	// Tickets contain no OIDC tokens, claims, or platform user/session data.
	record.BrowserHash, record.Verifier = "", ""
	ticket := oauth2.GenerateVerifier()
	if err := repository.SaveSiteAuthRecord(ctx, "ticket", ticket, *record, ticketTTL); err != nil {
		return "", err
	}
	target.Path, target.RawPath, target.RawQuery = SitePrefix+"complete", "", url.Values{"ticket": {ticket}}.Encode()
	return target.String(), nil
}

func validateRecord(ctx context.Context, record *model.SiteAuthRecord, routeID uint, host string) (*model.AuthSource, *url.URL, error) {
	if record.RouteID != routeID {
		return nil, nil, response.NewError(http.StatusUnauthorized, errInvalid)
	}
	source, err := loadSource(ctx, routeID)
	if err != nil {
		return nil, nil, err
	}
	if source.ID != record.SourceID || source.UpdatedAt.UTC().Format(time.RFC3339Nano) != record.SourceVersion {
		return nil, nil, response.NewError(http.StatusUnauthorized, errInvalid)
	}
	target, err := validateReturnURL(ctx, routeID, record.ReturnURL)
	if err != nil {
		return nil, nil, err
	}
	if host != "" && !strings.EqualFold(target.Hostname(), host) {
		return nil, nil, response.NewError(http.StatusUnauthorized, errInvalid)
	}
	return source, target, nil
}

// SessionInput is sent by the node, never populated from browser-supplied identity headers.
type SessionInput struct {
	RouteID uint   `json:"route_id" binding:"required"`
	Host    string `json:"host" binding:"required"`
	Token   string `json:"token" binding:"required"`
	Binding string `json:"binding"`
}

// SessionResult contains only a site-local opaque session and relative return path.
type SessionResult struct {
	Session    string `json:"session,omitempty"`
	ReturnPath string `json:"return_path,omitempty"`
	MaxAge     int    `json:"max_age,omitempty"`
}

func exchangeTicket(ctx context.Context, input SessionInput) (*SessionResult, error) {
	if !validToken(input.Token) {
		return nil, response.NewError(http.StatusUnauthorized, errInvalid)
	}
	record, err := repository.GetSiteAuthRecord(ctx, "ticket", input.Token, true)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(record.Binding), []byte(input.Binding)) != 1 {
		return nil, response.NewError(http.StatusUnauthorized, errInvalid)
	}
	_, target, err := validateRecord(ctx, record, input.RouteID, input.Host)
	if err != nil {
		return nil, err
	}
	session := oauth2.GenerateVerifier()
	if err := repository.SaveSiteAuthRecord(ctx, "session", session, *record, sessionTTL); err != nil {
		return nil, err
	}
	path := target.RequestURI()
	// Use an absolute-path reference, never a scheme-relative Location.
	if strings.HasPrefix(path, "//") {
		path = "/" + strings.TrimLeft(path, "/")
	}
	return &SessionResult{Session: session, ReturnPath: path, MaxAge: int(sessionTTL.Seconds())}, nil
}

func checkSession(ctx context.Context, input SessionInput) error {
	if !validToken(input.Token) {
		return response.NewError(http.StatusUnauthorized, errInvalid)
	}
	record, err := repository.GetSiteAuthRecord(ctx, "session", input.Token, false)
	if err != nil {
		return err
	}
	_, _, err = validateRecord(ctx, record, input.RouteID, input.Host)
	return err
}

func parseRouteID(raw string) (uint, error) {
	id, err := strconv.ParseUint(raw, 10, strconv.IntSize)
	if err != nil || id == 0 {
		return 0, errors.New(errInvalid)
	}
	return uint(id), nil
}
