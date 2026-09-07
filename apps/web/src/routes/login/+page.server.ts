import { fail, redirect } from '@sveltejs/kit';
import { authenticate, issueSession } from '$lib/server/auth';
import { loginSchema } from '$lib/forms/schemas';
import { setError, superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import type { Actions, PageServerLoad } from './$types';
const failures = new Map<string, { count: number; until: number }>();
const blocked = (key: string, now: number) => {
	const state = failures.get(key);
	return Boolean(state && state.until > now);
};
const recordFailure = (key: string, now: number) => {
	const count = (failures.get(key)?.count || 0) + 1;
	failures.set(key, { count, until: count >= 5 ? now + 300_000 : 0 });
};
export const load: PageServerLoad = async () => ({
	loginForm: await superValidate(zod4(loginSchema))
});
export const actions: Actions = {
	default: async ({ request, cookies, url, getClientAddress }) => {
		const addressKey = `address:${getClientAddress()}`;
		const now = Date.now();
		const form = await superValidate(request, zod4(loginSchema));
		if (!form.valid) return fail(400, { form });
		const accountKey = `account:${form.data.username.trim().toLowerCase()}`;
		if (blocked(addressKey, now) || blocked(accountKey, now))
			return setError(form, 'password', 'Too many attempts. Try again in a few minutes.');
		if (!(await authenticate(form.data.username, form.data.password))) {
			recordFailure(addressKey, now);
			recordFailure(accountKey, now);
			return setError(form, 'password', 'Incorrect username or password.');
		}
		failures.delete(addressKey);
		failures.delete(accountKey);
		await issueSession(
			cookies,
			form.data.username,
			url.protocol === 'https:' || process.env.FORCE_SECURE_COOKIES === '1'
		);
		redirect(303, '/');
	}
};
