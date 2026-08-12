import { clearSession } from '$lib/server/auth';
import { requireCsrf } from '$lib/server/operations';
import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ request, locals, cookies }) => {
	requireCsrf(await request.formData(), locals.csrf);
	clearSession(cookies);
	redirect(303, '/login');
};
