import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { senderSchema } from '$lib/forms/schemas';
import { loadConfig, saveConfig } from '$lib/server/config';
import { control, parseUsers } from '$lib/server/control';
import { errorMessage, requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async ({ locals }) => ({
	config: await loadConfig(),
	users: await control<{ users: string }>('/users')
		.then((v) => parseUsers(v.users))
		.catch(() => []),
	senderForm: await superValidate(
		{ csrf: locals.csrf || '', login: '', address: '' },
		zod4(senderSchema)
	)
});
export const actions: Actions = {
	add: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(senderSchema));
		if (!form.valid) return fail(400, { form });
		try {
			const f = new FormData();
			f.set('csrf', form.data.csrf);
			requireCsrf(f, locals.csrf);
			const c = await loadConfig();
			c.allowed_from[form.data.login] = [
				...new Set([...(c.allowed_from[form.data.login] || []), form.data.address.toLowerCase()])
			].sort();
			await saveConfig(c);
			return { form, success: true, message: 'Sender identity allowed.', config: c };
		} catch (error) {
			return fail(400, {
				form,
				error: errorMessage(error, 'Sender could not be saved.')
			});
		}
	},
	default: async ({ request, locals }) => {
		const f = await request.formData();
		try {
			requireCsrf(f, locals.csrf);
			const c = await loadConfig(),
				login = String(f.get('login')),
				address = String(f.get('address'));
			if (!(c.allowed_from[login] || []).includes(address))
				throw new Error('Allow the sender before making it default.');
			c.default_from[login] = address;
			await saveConfig(c);
			return { success: true, message: 'Default sender updated.', config: c };
		} catch (error) {
			return fail(400, { error: errorMessage(error, 'Default could not be updated.') });
		}
	},
	remove: async ({ request, locals }) => {
		const f = await request.formData();
		try {
			requireCsrf(f, locals.csrf);
			const c = await loadConfig(),
				login = String(f.get('login')),
				address = String(f.get('address'));
			c.allowed_from[login] = (c.allowed_from[login] || []).filter((x) => x !== address);
			if (!c.allowed_from[login].length) delete c.allowed_from[login];
			if (c.default_from[login] === address) delete c.default_from[login];
			await saveConfig(c);
			return { success: true, message: 'Sender identity removed.', config: c };
		} catch (error) {
			return fail(400, { error: errorMessage(error, 'Sender could not be removed.') });
		}
	}
};
