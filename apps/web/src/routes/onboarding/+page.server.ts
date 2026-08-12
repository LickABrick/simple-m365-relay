import { redirect } from '@sveltejs/kit';
import { loadConfig } from '$lib/server/config';
import { control, parseUsers } from '$lib/server/control';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = async () => {
	const config = await loadConfig();
	const [health, token, rawUsers] = await Promise.all([
		control<{ ok: boolean }>('/health').catch(() => ({ ok: false })),
		control<Record<string, unknown>>('/token/status').catch(() => ({})),
		control<{ users: string }>('/users').catch(() => ({ users: '' }))
	]);
	return {
		config,
		health: health.ok,
		token,
		users: parseUsers(rawUsers.users),
		steps: [
			{
				href: '/onboarding/relay',
				label: 'Relay identity',
				complete: Boolean(config.hostname && config.domain && config.relayhost)
			},
			{
				href: '/onboarding/network',
				label: 'Trust boundary',
				complete: Boolean(config.mynetworks.length)
			},
			{
				href: '/onboarding/microsoft',
				label: 'Microsoft 365',
				complete: Boolean(
					config.ms365_smtp_user && config.oauth.tenant_id && config.oauth.client_id
				)
			},
			{
				href: '/onboarding/authorize',
				label: 'Authorize OAuth',
				complete: Boolean(Object.keys(token).length)
			},
			{
				href: '/onboarding/client',
				label: 'First SMTP client',
				complete: parseUsers(rawUsers.users).length > 0
			},
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
