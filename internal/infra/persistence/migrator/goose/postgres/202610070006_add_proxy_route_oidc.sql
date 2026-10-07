-- +goose Up
ALTER TABLE of_proxy_routes ADD COLUMN oidc_auth_source_id BIGINT;
CREATE INDEX idx_of_proxy_routes_oidc_auth_source_id ON of_proxy_routes (oidc_auth_source_id);

-- +goose Down
DROP INDEX idx_of_proxy_routes_oidc_auth_source_id;
ALTER TABLE of_proxy_routes DROP COLUMN oidc_auth_source_id;
