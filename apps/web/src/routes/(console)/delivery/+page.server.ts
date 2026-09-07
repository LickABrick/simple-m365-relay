import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { testMailSchema } from '$lib/forms/schemas';
import { loadConfig } from '$lib/server/config';
import { control } from '$lib/server/control';
import { errorMessage, requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async ({ locals }) => {
	const c = await loadConfig();
	return {
		testForm: await superValidate(
			{
				csrf: locals.csrf || '',
				to_addr: '',
				from_addr: c.ms365_smtp_user,
				subject: 'Simple M365 Relay test',
				body: 'This message verifies the Simple M365 Relay delivery path.'
			},
			zod4(testMailSchema)
		)
	};
};
export const actions: Actions = {
	default: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(testMailSchema));
		if (!form.valid) return fail(400, { form });
		try {
			const f = new FormData();
			f.set('csrf', form.data.csrf);
			requireCsrf(f, locals.csrf);
			const result = await control<Record<string, unknown>>('/testmail', {
				to_addr: form.data.to_addr,
				from_addr: form.data.from_addr,
				subject: form.data.subject,
				body: form.data.body
			});
			return { form, success: true, message: 'Test message accepted.', delivery: result };
		} catch (error) {
			return fail(400, { form, error: errorMessage(error, 'Test message failed.') });
		}
	}
};
