import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { dataDir } from './files';

const base = (process.env.POSTFIX_CONTROL_URL || 'http://postfix:18080').replace(/\/$/, '');

async function token(): Promise<string> {
	return (
		process.env.CONTROL_TOKEN?.trim() ||
		(await readFile(join(dataDir, 'state', 'control.token'), 'utf8')).trim()
	);
}

export async function control<T = Record<string, unknown>>(
	path: string,
	body?: unknown
): Promise<T> {
	const response = await fetch(`${base}${path}`, {
		method: body === undefined ? 'GET' : 'POST',
		headers: {
			'X-Control-Token': await token(),
			...(body === undefined ? {} : { 'Content-Type': 'application/json' })
		},
		body: body === undefined ? undefined : JSON.stringify(body),
		signal: AbortSignal.timeout(15_000)
	});
	const result = await response
		.json()
		.catch(() => ({ error: `Control service returned ${response.status}.` }));
	if (!response.ok)
		throw new Error(String(result.error || `Control service returned ${response.status}.`));
	return result as T;
}

export function parseUsers(raw: string): string[] {
	return [
		...new Set(
			raw
				.split('\n')
				.map((line) => line.split(':', 1)[0].trim())
				.filter(Boolean)
		)
	].sort();
}
