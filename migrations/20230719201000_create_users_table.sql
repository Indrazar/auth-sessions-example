CREATE TABLE IF NOT EXISTS users(
  user_id           TEXT NOT NULL UNIQUE PRIMARY KEY,
  username          TEXT NOT NULL UNIQUE,
  display_name      TEXT NOT NULL UNIQUE,
  email             TEXT NOT NULL,
  verified          BOOLEAN NOT NULL,
  password_hash     TEXT NOT NULL,
  button_presses    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS active_sesssions(
  session_id        TEXT NOT NULL UNIQUE PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(user_id),
  expiry            DATETIME NOT NULL
);
