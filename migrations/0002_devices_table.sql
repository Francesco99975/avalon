CREATE TABLE IF NOT EXISTS devices(
id TEXT NOT NULL UNIQUE,
userId TEXT NOT NULL,
created TIMESTAMP NOT NULL,
PRIMARY KEY(id),
CONSTRAINT ud_fk FOREIGN KEY(userId) REFERENCES Users(id)
);