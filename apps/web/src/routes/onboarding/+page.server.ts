import { redirect } from '@sveltejs/kit';
import { loadConfig } from '$lib/server/config';
import { control, parseUsers } from '$lib/server/control';
import { evaluateReadiness } from '$lib/server/readiness';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = async () => {
	const config = await loadConfig();
	const [health, token, rawUsers] = await Promise.all([
		control<{ ok: boolean }>('/health').catch(() => ({ ok: false })),
		control<Record<string, unknown>>('/token/status').catch((): Record<string, unknown> => ({})),
		control<{ users: string }>('/users').catch(() => ({ users: '' }))
	]);
	const users = parseUsers(rawUsers.users);
	const readiness = evaluateReadiness(config, { tokenPresent: token['ok'] === true, users });
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
