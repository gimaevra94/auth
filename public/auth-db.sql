CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    login VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    passwordHash VARCHAR(255) NULL,
    temporaryUserID VARCHAR(255) NOT NULL UNIQUE,
    permanentUserID VARCHAR(255) NOT NULL UNIQUE,
    temporaryCancelled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE refresh_token (
    refreshToken VARCHAR(255) PRIMARY KEY,
    permanentUserID VARCHAR(255) NOT NULL,
    deviceInfo VARCHAR(255) NOT NULL DEFAULT '',
    tokenCancelled BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (permanentUserID) REFERENCES user(permanentUserID)
);

CREATE TABLE reset_token (
    token VARCHAR(255) PRIMARY KEY,
    cancelled BOOLEAN NOT NULL DEFAULT FALSE
);