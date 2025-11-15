CREATE TABLE user (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    login VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    passwordHash VARCHAR(255) NULL,
    temporaryId VARCHAR(255) NOT NULL UNIQUE,
    permanentId VARCHAR(255) NOT NULL UNIQUE,
    temporaryIdCancelled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE refresh_token (
    refreshToken VARCHAR(255) PRIMARY KEY,
    permanentId VARCHAR(255) NOT NULL,
    userAgent VARCHAR(255) NOT NULL DEFAULT '',
    refreshTokenCancelled BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (permanentId) REFERENCES user(permanentId)
);

CREATE TABLE reset_token (
    resetToken VARCHAR(255) PRIMARY KEY,
    resetTokenCancelled BOOLEAN NOT NULL DEFAULT FALSE
);