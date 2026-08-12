import Database from 'better-sqlite3';
import { building } from '$app/environment';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { migrate } from 'drizzle-orm/better-sqlite3/migrator';
import { chmodSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { dataDir } from './files';
import * as schema from './schema';

const databasePath =
	process.env.DATABASE_URL ||
	(building || process.env.NODE_ENV === 'test' ? ':memory:' : join(dataDir, 'state', 'relay.db'));
if (databasePath !== ':memory:') mkdirSync(dirname(databasePath), { recursive: true });
const sqlite = new Database(databasePath);
if (databasePath !== ':memory:') chmodSync(databasePath, 0o600);
sqlite.pragma('journal_mode = WAL');
sqlite.pragma('foreign_keys = ON');
sqlite.pragma('busy_timeout = 5000');
export const db = drizzle(sqlite, { schema });
let initialized = false;

export async function initializeDatabase(): Promise<void> {
	if (initialized) return;
	migrate(db, { migrationsFolder: process.env.MIGRATIONS_DIR || join(process.cwd(), 'drizzle') });
	const now = Math.floor(Date.now() / 1000);
	const authCount = sqlite.prepare('select count(*) as count from administrators').get() as {
		count: number;
	};
	if (!authCount.count) {
		try {
			const legacy = JSON.parse(readFileSync(join(dataDir, 'state', 'auth.json'), 'utf8'));
			if (legacy.username && legacy.password_hash)
				sqlite
					.prepare(
						'insert into administrators (id, username, password_hash, created_at) values (1, ?, ?, ?)'
					)
					.run(legacy.username, legacy.password_hash, legacy.created_at || now);
		} catch {
			/* fresh install */
		}
	}
	const settingsCount = sqlite.prepare('select count(*) as count from settings').get() as {
		count: number;
	};
	if (!settingsCount.count) {
		let config = JSON.stringify({
			hostname: 'relay.local',
			domain: 'local',
			mynetworks: ['127.0.0.0/8'],
			relayhost: '[smtp.office365.com]:587',
			ms365_smtp_user: '',
			tls: { smtpd_25: 'may', smtpd_587: 'encrypt' },
			oauth: { tenant_id: '', client_id: '', auto_refresh_minutes: 30 },
			allowed_from: {},
			default_from: {}
		});
		let appliedHash: string | null = null;
		let appliedConfig: string | null = null;
		try {
			config = readFileSync(join(dataDir, 'config', 'config.json'), 'utf8');
			console.warn(
				'[migration] Imported legacy config.json into SQLite. The legacy file is no longer used and can be deleted after verifying v2.'
			);
		} catch {
			/* fresh install */
		}
		try {
			appliedHash = readFileSync(join(dataDir, 'state', 'applied.hash'), 'utf8').trim() || null;
		} catch {
			/* absent */
		}
		try {
			appliedConfig = readFileSync(join(dataDir, 'state', 'applied_config.json'), 'utf8');
		} catch {
			/* absent */
		}
		sqlite
			.prepare(
				'insert into settings (id, config, applied_hash, applied_config, updated_at) values (1, ?, ?, ?, ?)'
			)
			.run(config, appliedHash, appliedConfig, now);
	}
	try {
		readFileSync(join(dataDir, 'config', 'config.json'));
		console.warn('[migration] Legacy config.json detected after SQLite import; it can be deleted.');
	} catch {
		/* no legacy file */
	}
	initialized = true;
}
