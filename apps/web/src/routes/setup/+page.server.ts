import { fail, redirect } from '@sveltejs/kit';
import { createAdmin, issueSession } from '$lib/server/auth';
import { setupSchema } from '$lib/forms/schemas';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async () => ({
	setupForm: await superValidate(zod4(setupSchema))
});
export const actions: Actions = {
	default: async ({ request, cookies, url }) => {
		const form = await superValidate(request, zod4(setupSchema));
		if (!form.valid) return fail(400, { form });
		await createAdmin(form.data.username, form.data.password);
		await issueSession(
			cookies,
			form.data.username,
			url.protocol === 'https:' || process.env.FORCE_SECURE_COOKIES === '1'
		);
		redirect(303, '/');
	}
};
