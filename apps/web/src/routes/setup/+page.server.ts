import { fail, redirect } from '@sveltejs/kit';
import { createAdmin, issueSession } from '$lib/server/auth';
import { setupSchema } from '$lib/forms/schemas';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import {
	consumeGeneratedSetupToken,
	getSetupToken,
	setupTokensMatch
} from '$lib/server/setup-token';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async () => {
	const bootstrapRequired = process.env.ALLOW_UNAUTHENTICATED_SETUP !== '1';
	const setupToken = bootstrapRequired ? await getSetupToken() : null;
	return {
		setupForm: await superValidate(zod4(setupSchema), { errors: false }),
		bootstrapRequired,
		setupTokenSource: setupToken?.source || 'unavailable'
	};
};
export const actions: Actions = {
	default: async ({ request, cookies, url }) => {
		const form = await superValidate(request, zod4(setupSchema));
		if (!form.valid) return fail(400, { form });
		let tokenSource = null;
		if (process.env.ALLOW_UNAUTHENTICATED_SETUP !== '1') {
			const setupToken = await getSetupToken();
			tokenSource = setupToken.source;
			if (!setupToken.token || !setupTokensMatch(form.data.bootstrapToken, setupToken.token))
				return fail(403, { form, error: 'The one-time setup token is incorrect.' });
		}
		await createAdmin(form.data.username, form.data.password);
		if (tokenSource) await consumeGeneratedSetupToken(tokenSource);
		await issueSession(
			cookies,
			form.data.username,
			url.protocol === 'https:' || process.env.FORCE_SECURE_COOKIES === '1'
		);
		redirect(303, '/');
	}
};
