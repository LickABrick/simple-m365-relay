import { timingSafeEqual } from 'node:crypto';
import { readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';

const tokenPath = () => join(process.env.DATA_DIR || '/data', 'state', 'setup.token');

export type SetupTokenSource = 'environment' | 'generated' | 'unavailable';

export async function getSetupToken(): Promise<{
	token: string | null;
	source: SetupTokenSource;
}> {
	const configured = process.env.SETUP_TOKEN?.trim();
	if (configured) return { token: configured, source: 'environment' };
	try {
		const generated = (await readFile(tokenPath(), 'utf8')).trim();
		return generated
			? { token: generated, source: 'generated' }
			: { token: null, source: 'unavailable' };
	} catch {
		return { token: null, source: 'unavailable' };
	}
}

export function setupTokensMatch(supplied: string, expected: string): boolean {
	const left = Buffer.from(supplied);
	const right = Buffer.from(expected);
	return left.length === right.length && timingSafeEqual(left, right);
}

export async function consumeGeneratedSetupToken(source: SetupTokenSource): Promise<void> {
	if (source !== 'generated') return;
	await unlink(tokenPath()).catch(() => undefined);
}
