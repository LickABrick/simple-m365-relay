import { fail, redirect } from '@sveltejs/kit';
import { createAdmin, issueSession } from '$lib/server/auth';
import { setupSchema } from '$lib/forms/schemas';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async () => ({
	setupForm: await superValidate(zod4(setupSchema)),
	bootstrapRequired: process.env.ALLOW_UNAUTHENTICATED_SETUP !== '1'
});
export const actions: Actions = {
	default: async ({ request, cookies, url }) => {
		const form = await superValidate(request, zod4(setupSchema));
		if (!form.valid) return fail(400, { form });
		if (process.env.ALLOW_UNAUTHENTICATED_SETUP !== '1') {
			const expected = process.env.SETUP_TOKEN?.trim();
			if (!expected || form.data.bootstrapToken !== expected)
				return fail(403, { form, error: 'The one-time setup token is incorrect.' });
		}
		await createAdmin(form.data.username, form.data.password);
		await issueSession(
			cookies,
			form.data.username,
			url.protocol === 'https:' || process.env.FORCE_SECURE_COOKIES === '1'
		);
		redirect(303, '/');
	}
};
