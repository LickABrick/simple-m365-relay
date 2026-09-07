import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { hash, verify } from '@node-rs/argon2';
import { eq, sql } from 'drizzle-orm';
import type { Cookies } from '@sveltejs/kit';
import { ensureSecret } from './files';
import { db } from './database';
import { administrators } from './schema';
export const sessionCookie = 'sm365r_session_v2';
const maxAge = 60 * 60 * 24 * 7;

type Session = { username: string; csrf: string; expires: number; version: number };

const encode = (value: Buffer | string) => Buffer.from(value).toString('base64url');

export async function adminExists(): Promise<boolean> {
	return Boolean(db.select({ id: administrators.id }).from(administrators).get());
}

export async function createAdmin(username: string, password: string): Promise<void> {
	db.insert(administrators)
		.values({
			id: 1,
			username,
			passwordHash: await hash(password),
			sessionVersion: 1,
			createdAt: Math.floor(Date.now() / 1000)
		})
		.run();
}

export async function authenticate(username: string, password: string): Promise<boolean> {
	const admin = db.select().from(administrators).get();
	if (!admin || admin.username !== username) return false;
	try {
		return await verify(admin.passwordHash, password);
	} catch {
		return false;
	}
}

export async function changeAdminPassword(
	username: string,
	currentPassword: string,
	password: string
): Promise<boolean> {
	if (!(await authenticate(username, currentPassword))) return false;
	db.update(administrators)
		.set({
			passwordHash: await hash(password),
			sessionVersion: sql`${administrators.sessionVersion} + 1`
		})
		.where(eq(administrators.username, username))
		.run();
	return true;
}

export function validatePassword(password: string): string | null {
	if (password.length < 12) return 'Use at least 12 characters.';
	if (password.toLowerCase() === password || password.toUpperCase() === password)
		return 'Include upper and lower case letters.';
	if (!/\d/.test(password)) return 'Include at least one number.';
	if (!/[^A-Za-z0-9]/.test(password)) return 'Include at least one symbol.';
	return null;
}

export async function issueSession(
	cookies: Cookies,
	username: string,
	secure: boolean
): Promise<void> {
	const admin = db.select().from(administrators).where(eq(administrators.username, username)).get();
	if (!admin) throw new Error('Administrator account is unavailable.');
	const payload: Session = {
		username,
		csrf: randomBytes(24).toString('base64url'),
		expires: Date.now() + maxAge * 1000,
		version: admin.sessionVersion
	};
	const body = encode(JSON.stringify(payload));
	const signature = createHmac('sha256', await ensureSecret())
		.update(body)
		.digest('base64url');
	cookies.set(sessionCookie, `${body}.${signature}`, {
		path: '/',
		httpOnly: true,
		sameSite: 'strict',
		secure,
		maxAge
	});
}

export async function readSession(cookies: Cookies): Promise<Session | null> {
	const token = cookies.get(sessionCookie);
	if (!token) return null;
	const [body, signature] = token.split('.');
	if (!body || !signature) return null;
	const expected = createHmac('sha256', await ensureSecret())
		.update(body)
		.digest();
	let supplied: Buffer;
	try {
		supplied = Buffer.from(signature, 'base64url');
	} catch {
		return null;
	}
	if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
	try {
		const session = JSON.parse(Buffer.from(body, 'base64url').toString()) as Session;
		if (!session.username || !session.csrf || session.expires <= Date.now()) return null;
		const admin = db
			.select()
			.from(administrators)
			.where(eq(administrators.username, session.username))
			.get();
		return admin && session.version === admin.sessionVersion ? session : null;
	} catch {
		return null;
	}
}

export function clearSession(cookies: Cookies): void {
	cookies.delete(sessionCookie, { path: '/' });
}
