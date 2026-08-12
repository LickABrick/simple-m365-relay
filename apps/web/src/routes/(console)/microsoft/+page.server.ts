import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { microsoftSettingsSchema } from '$lib/forms/schemas';
import { loadConfig, saveConfig } from '$lib/server/config';
import { control } from '$lib/server/control';
import { errorMessage, requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';
const safe = async <T>(p: Promise<T>, fallback: T) => {
	try {
		return await p;
	} catch {
		return fallback;
	}
};
export const load: PageServerLoad = async ({ locals }) => {
	const c = await loadConfig();
	return {
		token: await safe(control<Record<string, unknown>>('/token/status'), {}),
		deviceLog: (await safe(control<{ log: string }>('/device-flow-log'), { log: '' })).log,
		refreshLog: (await safe(control<{ log: string }>('/token/refresh-log'), { log: '' })).log,
		microsoftForm: await superValidate(
			{
				csrf: locals.csrf || '',
				ms365_smtp_user: c.ms365_smtp_user,
				tenant_id: c.oauth.tenant_id,
				client_id: c.oauth.client_id,
				auto_refresh_minutes: c.oauth.auto_refresh_minutes
			},
			zod4(microsoftSettingsSchema)
		)
	};
};
export const actions: Actions = {
	save: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(microsoftSettingsSchema));
		if (!form.valid) return fail(400, { form });
		try {
			const f = new FormData();
			f.set('csrf', form.data.csrf);
			requireCsrf(f, locals.csrf);
			const c = await loadConfig();
			c.ms365_smtp_user = form.data.ms365_smtp_user;
			c.oauth = {
				tenant_id: form.data.tenant_id,
				client_id: form.data.client_id,
				auto_refresh_minutes: form.data.auto_refresh_minutes
			};
			await saveConfig(c);
			return { form, success: true, message: 'Microsoft configuration saved.' };
		} catch (error) {
			return fail(400, {
				form,
				error: errorMessage(error, 'Microsoft settings could not be saved.')
			});
		}
	},
	start: async ({ request, locals }) => {
		const f = await request.formData();
		try {
			requireCsrf(f, locals.csrf);
			await control('/token/start', {});
			return {
				success: true,
				message: 'Device authorization started. Live progress appears below.'
			};
		} catch (error) {
			return fail(400, { error: errorMessage(error, 'Device authorization could not start.') });
		}
	},
	refresh: async ({ request, locals }) => {
		const f = await request.formData();
		try {
			requireCsrf(f, locals.csrf);
			await control('/token/refresh', {});
			return { success: true, message: 'Token refresh requested.' };
		} catch (error) {
			return fail(400, { error: errorMessage(error, 'Token refresh failed.') });
		}
	}
};
