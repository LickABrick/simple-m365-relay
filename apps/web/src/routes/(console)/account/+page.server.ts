import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { changePasswordSchema } from '$lib/forms/schemas';
import { changeAdminPassword, issueSession } from '$lib/server/auth';
import { requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => ({
	passwordForm: await superValidate(
		{ csrf: locals.csrf || '', currentPassword: '', password: '', confirm: '' },
		zod4(changePasswordSchema),
		{ errors: false }
	)
});

const attempts = new Map<string, { count: number; blockedUntil: number }>();
export const actions: Actions = {
	default: async ({ request, locals, cookies, url }) => {
		const form = await superValidate(request, zod4(changePasswordSchema));
		if (!form.valid) return fail(400, { form });
		const csrf = new FormData();
		csrf.set('csrf', form.data.csrf);
		requireCsrf(csrf, locals.csrf);
		const key = locals.user || 'unknown';
		const state = attempts.get(key);
		if (state && state.blockedUntil > Date.now())
			return fail(429, { form, error: 'Too many password attempts. Try again in five minutes.' });
		if (
			!locals.user ||
			!(await changeAdminPassword(locals.user, form.data.currentPassword, form.data.password))
		) {
			const count = (state?.count || 0) + 1;
			attempts.set(key, { count, blockedUntil: count >= 5 ? Date.now() + 300_000 : 0 });
			return fail(400, { form, error: 'The current password is incorrect.' });
		}
		attempts.delete(key);
		await issueSession(
			cookies,
			locals.user,
			url.protocol === 'https:' || process.env.FORCE_SECURE_COOKIES === '1'
		);
		return { form, success: true, message: 'Administrator password changed.' };
	}
};
