import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { relaySettingsSchema } from '$lib/forms/schemas';
import { hasPendingChanges, loadConfig, saveConfig } from '$lib/server/config';
import {
	applyAction,
	discardAction,
	errorMessage,
	requireCsrf,
	validateAction
} from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => {
	const config = await loadConfig();
	return {
		pending: await hasPendingChanges(config),
		settingsForm: await superValidate(
			{
				csrf: locals.csrf || '',
				hostname: config.hostname,
				domain: config.domain,
				relayhost: config.relayhost
			},
			zod4(relaySettingsSchema)
		)
	};
};
export const actions: Actions = {
	save: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(relaySettingsSchema));
		if (!form.valid) return fail(400, { settingsForm: form });
		try {
			const csrf = new FormData();
			csrf.set('csrf', form.data.csrf);
			requireCsrf(csrf, locals.csrf);
			if (/[^\x20-\x7e]/.test(`${form.data.hostname}${form.data.domain}${form.data.relayhost}`))
				throw new Error('Control characters are not allowed.');
			const config = await loadConfig();
			await saveConfig({
				...config,
				hostname: form.data.hostname,
				domain: form.data.domain,
				relayhost: form.data.relayhost
			});
			return { success: true, message: 'Relay identity saved. Validate before applying.' };
		} catch (error) {
			return fail(400, {
				settingsForm: form,
				error: errorMessage(error, 'Relay settings could not be saved.')
			});
		}
	},
	validate: validateAction,
	apply: applyAction,
	discard: discardAction
};
