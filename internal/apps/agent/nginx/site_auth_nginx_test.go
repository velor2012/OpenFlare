// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package nginx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rain-kl/Wavelet/internal/shared/response"
	openresty "github.com/Rain-kl/Wavelet/pkg/render/openresty"
)

// Run with an OpenResty binary on PATH (e.g. in the Agent base image).
func TestSiteAuthWithOpenResty(t *testing.T) {
	binary, err := exec.LookPath("openresty")
	if err != nil {
		t.Skip("OpenResty not installed")
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "app.example.com"}, DNSNames: []string{"app.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	var controlStatus atomic.Int32
	controlStatus.Store(http.StatusOK)
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Token   string `json:"token"`
			Binding string `json:"binding"`
			Host    string `json:"host"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || input.Host != "app.example.com" {
			t.Error("control request leaked client headers or lost site host")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(controlStatus.Load()))
		if strings.HasSuffix(r.URL.Path, "/check") && input.Token == "malformed" {
			_, _ = w.Write([]byte("not-json"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/exchange") {
			if input.Binding == "" {
				t.Error("exchange request missing browser binding")
			}
			_ = json.NewEncoder(w).Encode(response.OK(map[string]any{"session": "new-session", "return_path": "/private", "max_age": 3600}))
		} else {
			_ = json.NewEncoder(w).Encode(response.OKNil())
		}
	}))
	t.Cleanup(control.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "origin cookie=%s", r.Header.Get("Cookie"))
	}))
	t.Cleanup(origin.Close)
	sourceID := uint64(1)
	route := openresty.Route{ID: 1, SiteName: "private", Domains: []string{"app.example.com"}, OriginURL: origin.URL, Enabled: true, EnableHTTPS: true, RedirectHTTP: true, DomainCertIDs: []uint{1}, OIDCAuthSourceID: &sourceID, OIDCAuthURL: control.URL}
	config, err := openresty.RenderRouteConfig(openresty.Document{Routes: []openresty.Route{route}}, []openresty.SupportFile{{Path: "1.crt", Content: certPEM}, {Path: "1.key", Content: keyPEM}})
	if err != nil {
		t.Fatal(err)
	}
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listen.Addr().(*net.TCPAddr).Port
	_ = listen.Close()
	config = strings.NewReplacer(openresty.LuaDirPlaceholder, dir, openresty.CertDirPlaceholder, dir, "listen 443 ssl;", fmt.Sprintf("listen 127.0.0.1:%d ssl;", port), "listen 80;", "listen 127.0.0.1:0;", "/etc/ssl/certs/ca-certificates.crt", filepath.Join(dir, "ca.crt")).Replace(config)
	// httptest's bundled certificate uses the DNS SAN example.com. Keep TLS
	// verification enabled and set its test-only name explicitly.
	config = strings.ReplaceAll(config, "proxy_ssl_name 127.0.0.1;", "proxy_ssl_name example.com;")
	// Pages API locations can rewrite before proxying; they must inherit the
	// site guard too, rather than skipping it through a native rewrite break.
	config = strings.ReplaceAll(config, "    location / {", "    location /api {\n        rewrite ^/api/(.*)$ /$1 break;\n        proxy_set_header Cookie $openflare_origin_cookie;\n        proxy_pass "+origin.URL+";\n    }\n    location / {")
	// No privileged port is needed; remove the HTTP redirect block for this TLS test.
	start := strings.Index(config, "server {\n    listen 127.0.0.1:0;")
	if start >= 0 {
		end := strings.Index(config[start:], "}\n\n")
		config = config[:start] + config[start+end+3:]
	}
	if err := os.Mkdir(filepath.Join(dir, "site_auth"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "waf"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"1.crt": certPEM, "1.key": keyPEM, "ca.crt": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: control.Certificate().Raw})), "site_auth/runtime.lua": siteAuthRuntimeLua, "waf/check.lua": "return", "nginx.conf": "user root;\nworker_processes 1;\nerror_log stderr;\npid " + filepath.Join(dir, "nginx.pid") + ";\nevents { worker_connections 128; }\nhttp { map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n" + config + "\n}"}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binary, "-p", dir, "-c", filepath.Join(dir, "nginx.conf"), "-g", "daemon off;")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	address := fmt.Sprintf("https://127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := client.Get(address)
		if err == nil {
			_ = res.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	request := func(path, cookie string, want int) string {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "app.example.com"
		req.Header.Set("Cookie", cookie)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Errorf("OpenResty %s = %d, %s, want %d", path, res.StatusCode, body, want)
		}
		return string(body)
	}
	request("/private", "", 302)
	request("/api/private", "", 302)
	request("/api/private", "__Host-openflare_site_1=valid; app=keep", 200)
	if body := request("/private", "__Host-openflare_site_1=valid; app=keep", 200); body != "origin cookie=app=keep" {
		t.Errorf("authenticated origin = %q, want filtered cookies", body)
	}
	request("/openflare/site-auth/_check", "", 404)
	request("/openflare/site-auth/complete?ticket=test", "__Host-openflare_challenge_1=challenge", 302)
	request("/private", "__Host-openflare_site_1=malformed", 503)
	controlStatus.Store(503)
	request("/private", "__Host-openflare_site_1=valid", 503)
}
