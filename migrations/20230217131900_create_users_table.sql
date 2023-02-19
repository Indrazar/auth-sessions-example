CREATE TABLE IF NOT EXISTS users(
  user_id           TEXT NOT NULL UNIQUE PRIMARY KEY,
  username          TEXT NOT NULL UNIQUE,
  displayname       TEXT NOT NULL UNIQUE,
  email             TEXT NOT NULL,
  verified          BOOLEAN NOT NULL,
  password_hash     TEXT NOT NULL
);