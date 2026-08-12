import { redirect, type Handle } from '@sveltejs/kit';
import { adminExists, readSession } from '$lib/server/auth';
import { initializeDatabase } from '$lib/server/database';

const publicPaths = new Set(['/login', '/setup', '/healthz']);

export const handle: Handle = async ({ event, resolve }) => {
	await initializeDatabase();
	const session = await readSession(event.cookies);
	event.locals.user = session?.username || null;
	event.locals.csrf = session?.csrf || null;
	const configured = await adminExists();
	if (!configured && event.url.pathname !== '/setup' && event.url.pathname !== '/healthz')
		redirect(303, '/setup');
	if (configured && event.url.pathname === '/setup')
		redirect(303, event.locals.user ? '/' : '/login');
	if (!event.locals.user && !publicPaths.has(event.url.pathname)) redirect(303, '/login');

	const response = await resolve(event);
	response.headers.set('X-Content-Type-Options', 'nosniff');
	response.headers.set('Referrer-Policy', 'same-origin');
	response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
	response.headers.set(
		'Content-Security-Policy',
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
	);
	return response;
};
