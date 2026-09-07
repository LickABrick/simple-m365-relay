import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { relaySettingsSchema } from '$lib/forms/schemas';
import {
	diffConfig,
	hasPendingChanges,
	loadAppliedConfig,
	loadConfig,
	saveConfig
} from '$lib/server/config';
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
	const applied = await loadAppliedConfig();
	return {
		pending: await hasPendingChanges(config),
		diff: diffConfig(applied, config),
		hasAppliedSnapshot: applied !== null,
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
		if (!form.valid) return fail(400, { form });
		try {
			const csrf = new FormData();
			csrf.set('csrf', form.data.csrf);
			requireCsrf(csrf, locals.csrf);
			if (/[^\x20-\x7e]/.test(`${form.data.hostname}${form.data.domain}${form.data.relayhost}`))
				throw new Error('Control characters are not allowed.');
			const config = await loadConfig();
			const saved = {
				...config,
				hostname: form.data.hostname,
				domain: form.data.domain,
				relayhost: form.data.relayhost
			};
			await saveConfig(saved);
			return {
				form,
				success: true,
				message: 'Relay identity saved. Review the pending changes before applying.',
				pending: await hasPendingChanges(saved),
				diff: diffConfig(await loadAppliedConfig(), saved)
			};
		} catch (error) {
			return fail(400, {
				form,
				error: errorMessage(error, 'Relay settings could not be saved.')
			});
		}
	},
	validate: validateAction,
	apply: applyAction,
	discard: discardAction
};
