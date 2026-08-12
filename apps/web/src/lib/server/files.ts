import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export const dataDir =
	process.env.DATA_DIR ||
	(process.env.NODE_ENV === 'production' ? '/data' : join(process.cwd(), '.data'));
export const stateDir = join(dataDir, 'state');
export const configPath = join(dataDir, 'config', 'config.json');

export async function readJson<T>(path: string, fallback: T): Promise<T> {
	try {
		return JSON.parse(await readFile(path, 'utf8')) as T;
	} catch {
		return fallback;
	}
}

export async function writeJson(path: string, value: unknown): Promise<void> {
	await mkdir(dirname(path), { recursive: true });
	const temporary = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
	await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
	await rename(temporary, path);
}

export async function ensureSecret(): Promise<Buffer> {
	const path = join(stateDir, 'secret.key');
	try {
		return await readFile(path);
	} catch {
		await mkdir(stateDir, { recursive: true });
		const secret = randomBytes(32);
		try {
			const handle = await open(path, 'wx', 0o600);
			await handle.writeFile(secret);
			await handle.close();
			return secret;
		} catch {
			return readFile(path);
		}
	}
}

export function stableHash(value: unknown): string {
	const normalize = (entry: unknown): unknown => {
		if (Array.isArray(entry)) return entry.map(normalize);
		if (entry && typeof entry === 'object') {
			return Object.fromEntries(
				Object.entries(entry as Record<string, unknown>)
					.sort(([a], [b]) => a.localeCompare(b))
					.map(([key, child]) => [key, normalize(child)])
			);
		}
		return entry;
	};
	return createHash('sha256')
		.update(JSON.stringify(normalize(value)))
		.digest('hex');
}
