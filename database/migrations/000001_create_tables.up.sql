PRAGMA foreign_keys = ON;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS nonces (
  nonce VARCHAR(255) NOT NULL PRIMARY KEY,
  expiration TIMESTAMP NOT NULL,
  ref VARCHAR(255) -- A nonce can be associated with something.
);

CREATE TABLE IF NOT EXISTS routes (
  user_address VARCHAR(255) NOT NULL,
  route VARCHAR(255) NOT NULL,
  port INTEGER NOT NULL,
  PRIMARY KEY (user_address, route, port)
);
COMMIT;
