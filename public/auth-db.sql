CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    login VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(128) NOT NULL UNIQUE,
    passwordHash VARCHAR(255) NULL,
    temporaryUserID VARCHAR(255) NOT NULL UNIQUE,
    permanentUserID VARCHAR(255) NOT NULL UNIQUE,
    temporaryCancelled BOOLEAN DEFAULT FALSE
);

CREATE TABLE refresh_token (
    FOREIGN KEY (permanentUserID) REFERENCES user(permanentUserID),
    refreshToken VARCHAR(255) PRIMARY KEY,
    permanentUserID VARCHAR(255) NOT NULL,
    deviceInfo VARCHAR(255),
    tokenCancelled BOOLEAN DEFAULT FALSE
);

CREATE TABLE reset_token (
    token VARCHAR(255) PRIMARY KEY,
    cancelled BOOLEAN DEFAULT FALSE
);