import Database from 'better-sqlite3';
import { existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

const dataDir = process.env.DATA_DIR || '/data';
const databasePath = process.env.DATABASE_URL || join(dataDir, 'state', 'relay.db');
const [command, subcommand, confirmation] = process.argv.slice(2);

function usage() {
	console.error('Usage: relay-admin status | relay-admin admin reset --yes');
	process.exitCode = 2;
}

if (command === 'status' && !subcommand) {
	if (!existsSync(databasePath)) {
		console.log(JSON.stringify({ database: databasePath, initialized: false }, null, 2));
	} else {
		const db = new Database(databasePath, { readonly: true });
		const admin = db.prepare('select username, created_at from administrators limit 1').get();
		const settings = db.prepare('select applied_hash, updated_at from settings where id = 1').get();
		console.log(
			JSON.stringify({ database: databasePath, initialized: true, admin, settings }, null, 2)
		);
		db.close();
	}
} else if (command === 'admin' && subcommand === 'reset' && confirmation === '--yes') {
	if (!existsSync(databasePath)) throw new Error(`Database not found: ${databasePath}`);
	const db = new Database(databasePath);
	const result = db.prepare('delete from administrators').run();
	db.close();
	const secret = join(dataDir, 'state', 'secret.key');
	if (existsSync(secret)) unlinkSync(secret);
	console.log(
		`Administrator reset complete (${result.changes} account removed). Open /setup to recover access.`
	);
} else {
	usage();
}
