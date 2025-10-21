-- Migration: create password_reset_grants
-- Run this on your MySQL server (Aiven or Workbench)

CREATE TABLE IF NOT EXISTS `password_reset_grants` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(255) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `username_idx` (`username`),
  KEY `expires_at_idx` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Optional: automatic cleanup event (runs hourly) -- requires EVENT scheduler enabled.
-- If your managed DB (Aiven) does not allow enabling events, run a cron job or application-level cleanup.
-- Uncomment and run if permitted on your server:
--
-- DELIMITER $$
-- CREATE EVENT IF NOT EXISTS ev_cleanup_password_reset_grants
-- ON SCHEDULE EVERY 1 HOUR
-- DO
-- BEGIN
--   DELETE FROM password_reset_grants WHERE expires_at < NOW();
-- END$$
-- DELIMITER ;

-- NOTE:
-- - This migration assumes your application will insert and delete grants as implemented in server.js.
-- - No foreign key is used because `username` refers to either `tenants.username` or `admins.username`.
-- - After applying the migration, test the forgot-password flow: verify-username -> verify-otp -> reset-password.
