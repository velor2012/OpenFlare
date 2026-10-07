// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package model

// SiteAuthRecord is short-lived authentication state stored only in Redis.
// Site visitors are not platform users and never receive a platform session.
type SiteAuthRecord struct {
	RouteID       uint   `json:"route_id"`
	SourceID      uint64 `json:"source_id"`
	SourceVersion string `json:"source_version"`
	ReturnURL     string `json:"return_url"`
	Binding       string `json:"binding"`
	BrowserHash   string `json:"browser_hash,omitempty"`
	Verifier      string `json:"verifier,omitempty"`
}
