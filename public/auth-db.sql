CREATE TABLE login (
    permanentId CHAR(36) NOT NULL,
    login VARCHAR(64) NOT NULL,
    cancelled BOOLEAN NOT NULL
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4;

CREATE TABLE email (
    permanentId CHAR(36) NOT NULL,
    email VARCHAR(128) NOT NULL,
    yauth BOOLEAN NOT NULL,
    cancelled BOOLEAN NOT NULL
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4;

CREATE TABLE password_hash (
    permanentId CHAR(36) NOT NULL,
    passwordHash VARCHAR(255) NOT NULL,
    cancelled BOOLEAN NOT NULL
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4;

CREATE TABLE temporary_id (
    permanentId CHAR(36) NOT NULL,
    temporaryId CHAR(36) NOT NULL,
    userAgent VARCHAR(255) NOT NULL,
    yauth BOOLEAN NOT NULL,
    cancelled BOOLEAN NOT NULL
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4;

CREATE TABLE refresh_token (
    permanentId CHAR(36) NOT NULL,
    token VARCHAR(255) NOT NULL,
    userAgent VARCHAR(255) NOT NULL,
    yauth BOOLEAN NOT NULL,
    cancelled BOOLEAN NOT NULL
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4;

CREATE TABLE reset_token (
    token VARCHAR(255) NOT NULL,
    cancelled BOOLEAN NOT NULL
) ENGINE=INNODB DEFAULT CHARSET=utf8mb4;