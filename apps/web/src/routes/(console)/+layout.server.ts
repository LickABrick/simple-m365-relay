import type { LayoutServerLoad } from './$types';
import { control, parseUsers } from '$lib/server/control';
import { hasPendingChanges, loadConfig } from '$lib/server/config';
import { evaluateReadiness } from '$lib/server/readiness';
import { analyzeOAuthCapabilities, type TokenStatus } from '$lib/oauth-capabilities';

export const load: LayoutServerLoad = async ({ locals }) => {
	const config = await loadConfig();
	const [health, token, rawUsers] = await Promise.all([
		control<{ ok: boolean }>('/health').catch(() => ({ ok: false })),
		control<TokenStatus>('/token/status').catch((): TokenStatus => ({})),
		control<{ users: string }>('/users').catch(() => ({ users: '' }))
	]);
	const capabilities = analyzeOAuthCapabilities(config, token);
	return {
		user: locals.user,
		csrf: locals.csrf,
		version: process.env.APP_VERSION || '2.0.0',
		relayAvailable: health.ok,
		readiness: evaluateReadiness(config, {
			tokenPresent: token['ok'] === true,
			tokenReady: capabilities.tokenReady,
			users: parseUsers(rawUsers.users)
		}),
		pendingChanges: await hasPendingChanges(config)
	};
};
