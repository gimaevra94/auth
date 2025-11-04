CREATE TABLE user (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    login VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    passwordHash VARCHAR(255) NULL,
    temporaryUserId VARCHAR(255) NOT NULL UNIQUE,
    permanentUserId VARCHAR(255) NOT NULL UNIQUE,
    temporaryUserIdCancelled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE refresh_token (
    refreshToken VARCHAR(255) PRIMARY KEY,
    permanentUserId VARCHAR(255) NOT NULL,
    userAgent VARCHAR(255) NOT NULL DEFAULT '',
    refreshTokenCancelled BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (permanentUserId) REFERENCES user(permanentUserId)
);

CREATE TABLE reset_token (
    resetToken VARCHAR(255) PRIMARY KEY,
    resetrefreshTokenCancelled BOOLEAN NOT NULL DEFAULT FALSE
);