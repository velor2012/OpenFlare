// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	db "github.com/Rain-kl/Wavelet/internal/infra/persistence"
	"github.com/Rain-kl/Wavelet/internal/model"
)

func siteAuthKey(kind, token string) string {
	sum := sha256.Sum256([]byte(token))
	return db.PrefixedKey("site_auth:" + kind + ":" + hex.EncodeToString(sum[:]))
}

// AllowSiteAuthLogin limits public login starts without retaining client IPs.
func AllowSiteAuthLogin(ctx context.Context, ip string) (bool, error) {
	if db.Redis == nil {
		return false, errors.New("site authentication requires Redis")
	}
	const maxLoginsPerMinute = 20
	count, err := db.Redis.Eval(ctx, `local n = redis.call('INCR', KEYS[1]); if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end; return n`, []string{siteAuthKey("rate", ip)}).Int()
	return count <= maxLoginsPerMinute, err
}

// SaveSiteAuthRecord stores ephemeral state with an absolute lifetime.
func SaveSiteAuthRecord(ctx context.Context, kind, token string, record model.SiteAuthRecord, ttl time.Duration) error {
	if db.Redis == nil {
		return errors.New("site authentication requires Redis")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return db.Redis.Set(ctx, siteAuthKey(kind, token), data, ttl).Err()
}

// GetSiteAuthRecord atomically consumes states/tickets, or reads a session.
func GetSiteAuthRecord(ctx context.Context, kind, token string, consume bool) (*model.SiteAuthRecord, error) {
	if db.Redis == nil {
		return nil, errors.New("site authentication requires Redis")
	}
	key := siteAuthKey(kind, token)
	var data string
	var err error
	if consume {
		data, err = db.Redis.GetDel(ctx, key).Result()
	} else {
		data, err = db.Redis.Get(ctx, key).Result()
	}
	if err != nil {
		return nil, err
	}
	var record model.SiteAuthRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return nil, err
	}
	return &record, nil
}
