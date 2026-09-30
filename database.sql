-- Run this file in phpMyAdmin (Import tab or SQL tab).

CREATE DATABASE IF NOT EXISTS secure_auth
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE secure_auth;

CREATE TABLE IF NOT EXISTS users (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(100) NOT NULL,
    email      VARCHAR(150) NOT NULL UNIQUE,      -- UNIQUE: no two accounts share an email
    password   VARCHAR(255) NOT NULL,             -- stores the HASH (never the real password); 255 leaves room for future hash formats
    role       ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
