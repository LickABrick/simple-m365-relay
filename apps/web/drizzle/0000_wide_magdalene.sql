CREATE TABLE `administrators` (
	`id` integer PRIMARY KEY DEFAULT 1 NOT NULL,
	`username` text NOT NULL,
	`password_hash` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `administrators_username_unique` ON `administrators` (`username`);--> statement-breakpoint
CREATE TABLE `audit_events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`actor` text,
	`action` text NOT NULL,
	`outcome` text NOT NULL,
	`detail` text,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `settings` (
	`id` integer PRIMARY KEY DEFAULT 1 NOT NULL,
	`config` text NOT NULL,
	`applied_hash` text,
	`applied_config` text,
	`updated_at` integer NOT NULL
);
