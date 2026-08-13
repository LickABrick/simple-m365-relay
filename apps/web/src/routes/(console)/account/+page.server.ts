import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { changePasswordSchema } from '$lib/forms/schemas';
import { changeAdminPassword } from '$lib/server/auth';
import { requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => ({
	passwordForm: await superValidate(
		{ csrf: locals.csrf || '', currentPassword: '', password: '', confirm: '' },
		zod4(changePasswordSchema),
		{ errors: false }
	)
});

export const actions: Actions = {
	default: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(changePasswordSchema));
		if (!form.valid) return fail(400, { form });
		const csrf = new FormData();
		csrf.set('csrf', form.data.csrf);
		requireCsrf(csrf, locals.csrf);
		if (
			!locals.user ||
			!(await changeAdminPassword(locals.user, form.data.currentPassword, form.data.password))
		)
			return fail(400, { form, error: 'The current password is incorrect.' });
		return { form, success: true, message: 'Administrator password changed.' };
	}
};
