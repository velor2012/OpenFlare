// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package site_auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Rain-kl/Wavelet/internal/apps/oauth"
	db "github.com/Rain-kl/Wavelet/internal/infra/persistence"
	"github.com/Rain-kl/Wavelet/internal/model"
	"github.com/Rain-kl/Wavelet/internal/repository"
	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/go-jose/go-jose/v4"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func setupSiteAuth(t *testing.T) (*gorm.DB, *miniredis.Miniredis, *model.AuthSource) {
	t.Helper()
	conn, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{DisableForeignKeyConstraintWhenMigrating: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.AutoMigrate(&model.ProxyRoute{}, &model.ZoneDomain{}, &model.AuthSource{}, &model.SystemConfig{}); err != nil {
		t.Fatal(err)
	}
	previousDB, previousRedis := db.DB(context.Background()), db.Redis
	repository.StopSystemConfigCacheListener()
	repository.ResetSystemConfigRAMCacheForTest()
	db.SetDB(conn)
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	db.Redis = client
	t.Cleanup(func() {
		repository.StopSystemConfigCacheListener()
		repository.ResetSystemConfigRAMCacheForTest()
		db.Redis = previousRedis
		db.SetDB(previousDB)
		_ = client.Close()
		sqlDB, _ := conn.DB()
		_ = sqlDB.Close()
	})
	source := &model.AuthSource{ID: 1, Name: "casdoor", Type: "oidc", IsActive: true, ClientID: "site-client", ClientSecret: "test-secret"}
	for _, value := range []any{
		source,
		&model.ProxyRoute{ID: 1, SiteName: "site", OriginURL: "http://origin.test", Enabled: true, EnableHTTPS: true, RedirectHTTP: true, OIDCAuthSourceID: &source.ID},
		&model.ZoneDomain{ID: 1, ProxyRouteID: uintPtr(1), Domain: "app.example.com"},
		&model.SystemConfig{Key: model.ConfigKeyServerAddress, Value: "https://control.example.com"},
	} {
		if err := conn.Create(value).Error; err != nil {
			t.Fatal(err)
		}
	}
	return conn, mr, source
}

func uintPtr(value uint) *uint { return &value }

func TestSiteAuthOIDCFlow(t *testing.T) {
	conn, mr, source := setupSiteAuth(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, state, challenge string
	mode := "valid"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("redirect_uri") != "https://control.example.com"+Prefix+"callback" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
				t.Errorf("token exchange form = %v, want fixed callback and matching PKCE", r.Form)
			}
			claims := map[string]any{"iss": issuer, "sub": "casdoor/string-user", "aud": source.ClientID, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": state, "id": "external-string-id"}
			if mode == "wrong-nonce" {
				claims["nonce"] = "wrong"
			}
			if mode == "wrong-audience" {
				claims["aud"] = "other-client"
			}
			if mode == "expired" {
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
			}
			payload, _ := json.Marshal(claims)
			signed, signErr := signer.Sign(payload)
			if signErr != nil {
				t.Error(signErr)
				return
			}
			raw, serializeErr := signed.CompactSerialize()
			if serializeErr != nil {
				t.Error(serializeErr)
				return
			}
			response := map[string]any{"access_token": "test-access", "token_type": "Bearer", "id_token": raw}
			if mode == "missing-token" {
				delete(response, "id_token")
			}
			_ = json.NewEncoder(w).Encode(response)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	issuer = provider.URL
	t.Cleanup(func() { oauth.InvalidateOIDCProviderCache(issuer) })
	if err := conn.Model(source).Update("openid_discovery_url", issuer).Error; err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	browser := oauth2.GenerateVerifier()
	binding := hash("site-browser-challenge")
	for _, invalid := range []string{"http://app.example.com", "https://evil.example.com", "https://app.example.com.evil.test", "https://app.example.com:8443", "https://user@app.example.com", "https://app.example.com/openflare/site-auth/complete", "https://app.example.com/\\evil"} {
		if _, err := validateReturnURL(ctx, 1, invalid); err == nil {
			t.Errorf("validateReturnURL(%q) accepted, want rejected", invalid)
		}
	}
	start := func() {
		t.Helper()
		location, nextState, err := beginLogin(ctx, 1, "https://app.example.com/private?x=1", binding, browser)
		if err != nil {
			t.Fatal(err)
		}
		state = nextState
		parsed, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		challenge = parsed.Query().Get("code_challenge")
		if parsed.Query().Get("nonce") != state || parsed.Query().Get("code_challenge_method") != "S256" {
			t.Errorf("beginLogin() authorization parameters = %v, want nonce and S256 PKCE", parsed.Query())
		}
	}
	start()
	if _, err := finishLogin(ctx, state, "code", oauth2.GenerateVerifier()); err == nil {
		t.Error("finishLogin(wrong browser) accepted, want rejected")
	}
	location, err := finishLogin(ctx, state, "code", browser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := finishLogin(ctx, state, "code", browser); err == nil {
		t.Error("finishLogin(replayed state) accepted, want rejected")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "app.example.com" || parsed.Path != SitePrefix+"complete" {
		t.Errorf("finishLogin() = %q, want site-local completion", location)
	}
	input := SessionInput{RouteID: 1, Host: "app.example.com", Token: parsed.Query().Get("ticket"), Binding: binding}
	result, err := exchangeTicket(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReturnPath != "/private?x=1" || !validToken(result.Session) {
		t.Errorf("exchangeTicket() = %+v, want opaque session and original path", result)
	}
	if _, err := exchangeTicket(ctx, input); err == nil {
		t.Error("exchangeTicket(replay) accepted, want rejected")
	}
	input.Token = result.Session
	if err := checkSession(ctx, input); err != nil {
		t.Fatalf("checkSession(valid) = %v, want nil", err)
	}
	input.Host = "other.example.com"
	if err := checkSession(ctx, input); err == nil {
		t.Error("checkSession(other host) accepted, want rejected")
	}
	input.Host = "app.example.com"
	input.RouteID = 2
	if err := checkSession(ctx, input); err == nil {
		t.Error("checkSession(other route) accepted, want rejected")
	}
	input.RouteID = 1
	if err := conn.Model(source).Update("is_active", false).Error; err != nil {
		t.Fatal(err)
	}
	if err := checkSession(ctx, input); err == nil {
		t.Error("checkSession(disabled source) accepted, want rejected immediately")
	}
	if err := conn.Model(source).Update("is_active", true).Error; err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"missing-token", "wrong-nonce", "wrong-audience", "expired"} {
		mode = invalid
		start()
		if _, err := finishLogin(ctx, state, "code", browser); err == nil {
			t.Errorf("finishLogin(%s) accepted, want rejected", invalid)
		}
	}
	mode = "valid"
	start()
	location, err = finishLogin(ctx, state, "code", browser)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = url.Parse(location)
	input.Token, input.Binding = parsed.Query().Get("ticket"), "wrong-binding"
	if _, err := exchangeTicket(ctx, input); err == nil {
		t.Error("exchangeTicket(wrong binding) accepted, want rejected")
	}
	input.Token, input.Binding = result.Session, binding
	mr.FastForward(sessionTTL)
	if err := checkSession(ctx, input); err == nil {
		t.Error("checkSession(expired) accepted, want rejected")
	}
	for _, name := range mr.Keys() {
		if strings.Contains(name, result.Session) {
			t.Error("Redis key contains session token, want hashed key")
		}
	}
}

func TestSiteAuthLoginRateLimit(t *testing.T) {
	_, mr, _ := setupSiteAuth(t)
	ctx := context.Background()
	for index := 0; index < 20; index++ {
		if allowed, err := repository.AllowSiteAuthLogin(ctx, "test-client"); err != nil || !allowed {
			t.Fatalf("AllowSiteAuthLogin(attempt %d) = %v, %v, want true", index+1, allowed, err)
		}
	}
	if allowed, err := repository.AllowSiteAuthLogin(ctx, "test-client"); err != nil || allowed {
		t.Errorf("AllowSiteAuthLogin(attempt 21) = %v, %v, want false", allowed, err)
	}
	mr.FastForward(time.Minute)
	if allowed, err := repository.AllowSiteAuthLogin(ctx, "test-client"); err != nil || !allowed {
		t.Errorf("AllowSiteAuthLogin(after expiry) = %v, %v, want true", allowed, err)
	}
}
