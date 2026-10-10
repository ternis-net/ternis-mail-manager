-- MariaDB / MySQL Schema for Ternis Mail Manager & Virtual Mail Delivery
-- Compatible with Postfix and Dovecot

CREATE DATABASE IF NOT EXISTS `vmail` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `vmail`;

-- Virtual Domains
CREATE TABLE IF NOT EXISTS `domains` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `domain` VARCHAR(255) NOT NULL UNIQUE,
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Virtual Mailboxes / Users
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `domain_id` INT NOT NULL,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `maildir` VARCHAR(255) NOT NULL,
  `quota_bytes` BIGINT DEFAULT 10737418240,
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Virtual Aliases and Forwarders
CREATE TABLE IF NOT EXISTS `aliases` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `domain_id` INT NOT NULL,
  `source` VARCHAR(255) NOT NULL UNIQUE,
  `destination` TEXT NOT NULL,
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Postmaster Login Verification Codes (Multi-worker synchronized)
CREATE TABLE IF NOT EXISTS `verification_codes` (
  `domain` VARCHAR(255) PRIMARY KEY,
  `code` VARCHAR(16) NOT NULL,
  `attempts` INT DEFAULT 0,
  `expires_at` INT NOT NULL,
  `created_at` INT NOT NULL,
  `requester_ip` VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
