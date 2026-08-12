import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';

export const administrators = sqliteTable('administrators', {
	id: integer('id').primaryKey().default(1),
	username: text('username').notNull().unique(),
	passwordHash: text('password_hash').notNull(),
	createdAt: integer('created_at').notNull()
});
export const settings = sqliteTable('settings', {
	id: integer('id').primaryKey().default(1),
	config: text('config', { mode: 'json' }).$type<Record<string, unknown>>().notNull(),
	appliedHash: text('applied_hash'),
	appliedConfig: text('applied_config', { mode: 'json' }).$type<Record<string, unknown>>(),
	updatedAt: integer('updated_at').notNull()
});
export const auditEvents = sqliteTable('audit_events', {
	id: integer('id').primaryKey({ autoIncrement: true }),
	actor: text('actor'),
	action: text('action').notNull(),
	outcome: text('outcome').notNull(),
	detail: text('detail'),
	createdAt: integer('created_at').notNull()
});
