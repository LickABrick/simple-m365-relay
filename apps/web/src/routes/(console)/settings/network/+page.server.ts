import { fail } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import { networkSettingsSchema } from '$lib/forms/schemas';
import { hasPendingChanges, loadConfig, saveConfig } from '$lib/server/config';
import { errorMessage, requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ locals }) => {
	const config = await loadConfig();
	return {
		pending: await hasPendingChanges(config),
		networkForm: await superValidate(
			{
				csrf: locals.csrf || '',
				mynetworks: config.mynetworks.join('\n'),
				tls_25: config.tls.smtpd_25,
				tls_587: config.tls.smtpd_587
			},
			zod4(networkSettingsSchema)
		)
	};
};
export const actions: Actions = {
	default: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(networkSettingsSchema));
		if (!form.valid) return fail(400, { form });
		try {
			const csrf = new FormData();
			csrf.set('csrf', form.data.csrf);
			requireCsrf(csrf, locals.csrf);
			const networks = form.data.mynetworks.split(/[\s,]+/).filter(Boolean);
			if (
				!networks.length ||
				networks.length > 128 ||
				networks.some((value) => value.length > 128 || /[^0-9a-fA-F:./]/.test(value))
			)
				throw new Error('Enter valid CIDR-style trusted networks.');
			const config = await loadConfig();
			await saveConfig({
				...config,
				mynetworks: networks,
				tls: { smtpd_25: form.data.tls_25, smtpd_587: form.data.tls_587 }
			});
			return { form, success: true, message: 'Network and TLS policy saved.' };
		} catch (error) {
			return fail(400, {
				form,
				error: errorMessage(error, 'Network settings could not be saved.')
			});
		}
	}
};
