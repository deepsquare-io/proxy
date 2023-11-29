-- name: GetNonce :one
SELECT * FROM nonces WHERE nonce = ? AND expiration > ? LIMIT 1;

-- name: CreateNonce :exec
INSERT INTO nonces (nonce, expiration) VALUES (?, ?);

-- name: UpdateNonce :one
UPDATE nonces SET expiration = ? WHERE nonce = ? RETURNING nonce;

---

-- name: GetRoute :one
SELECT * FROM routes WHERE user_address = ? LIMIT 1;

-- name: SetRoute :one
UPDATE routes SET route = ?, port = ? WHERE user_address = ? RETURNING route;

-- name: CreateRoute :exec
INSERT INTO routes (user_address, route, port) VALUES (?, ?, ?);

-- name: IsPortUsed :one
SELECT COUNT(*) FROM routes WHERE port = ?;

-- name: CountRoute :one
SELECT COUNT(*) FROM routes;
