import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { smtpClientSchema } from '$lib/forms/schemas';
import { control, parseUsers } from '$lib/server/control';
import { errorMessage, requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => ({
	users: await control<{ users: string }>('/users')
		.then((value) => parseUsers(value.users))
		.catch(() => []),
	clientForm: await superValidate(
		{ csrf: locals.csrf || '', login: '', password: '' },
		zod4(smtpClientSchema)
	)
});
export const actions: Actions = {
	add: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(smtpClientSchema));
		if (!form.valid) return fail(400, { clientForm: form });
		try {
			const csrf = new FormData();
			csrf.set('csrf', form.data.csrf);
			requireCsrf(csrf, locals.csrf);
			await control('/users/add', { login: form.data.login, password: form.data.password });
			const users = await control<{ users: string }>('/users').then((value) =>
				parseUsers(value.users)
			);
			return { success: true, message: 'SMTP client saved.', users };
		} catch (error) {
			return fail(400, {
				clientForm: form,
				error: errorMessage(error, 'SMTP client could not be saved.')
			});
		}
	},
	delete: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			await control('/users/delete', { login: String(form.get('login') || '') });
			const users = await control<{ users: string }>('/users').then((value) =>
				parseUsers(value.users)
			);
			return { success: true, message: 'SMTP client removed.', users };
		} catch (error) {
			return fail(400, { error: errorMessage(error, 'SMTP client could not be removed.') });
		}
	}
};
