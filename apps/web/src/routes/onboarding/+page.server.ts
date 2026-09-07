import { redirect } from '@sveltejs/kit';
import { loadConfig } from '$lib/server/config';
import { control, parseUsers } from '$lib/server/control';
import { evaluateReadiness } from '$lib/server/readiness';
import type { PageServerLoad } from './$types';
import { analyzeOAuthCapabilities, type TokenStatus } from '$lib/oauth-capabilities';
export const load: PageServerLoad = async () => {
	const config = await loadConfig();
	const [health, token, rawUsers] = await Promise.all([
		control<{ ok: boolean }>('/health').catch(() => ({ ok: false })),
		control<TokenStatus>('/token/status').catch((): TokenStatus => ({})),
		control<{ users: string }>('/users').catch(() => ({ users: '' }))
	]);
	const users = parseUsers(rawUsers.users);
	const capabilities = analyzeOAuthCapabilities(config, token);
	const readiness = evaluateReadiness(config, {
		tokenPresent: token['ok'] === true,
		tokenReady: capabilities.tokenReady,
		users
	});
	return {
		config,
		health: health.ok,
		token,
		users,
		steps: [
			...readiness.checks,
			{
				href: '/onboarding/review',
				label: 'Readiness review',
				complete: Boolean(config.onboarding_complete)
			}
		]
	};
};
export const actions = {
	finish: async () => {
		redirect(303, '/onboarding/review');
	}
};
