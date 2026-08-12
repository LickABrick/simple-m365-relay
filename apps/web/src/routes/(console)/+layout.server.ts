import type { LayoutServerLoad } from './$types';
import { control, parseUsers } from '$lib/server/control';
import { hasPendingChanges, loadConfig } from '$lib/server/config';
import { evaluateReadiness } from '$lib/server/readiness';

export const load: LayoutServerLoad = async ({ locals }) => {
	const config = await loadConfig();
	const [health, token, rawUsers] = await Promise.all([
		control<{ ok: boolean }>('/health').catch(() => ({ ok: false })),
		control<Record<string, unknown>>('/token/status').catch(
			(): Record<string, unknown> => ({})
		),
		control<{ users: string }>('/users').catch(() => ({ users: '' }))
	]);
	return {
		user: locals.user,
		csrf: locals.csrf,
		version: process.env.APP_VERSION || '2.0.0-rc.1',
		relayAvailable: health.ok,
		readiness: evaluateReadiness(config, {
			tokenPresent: token['ok'] === true,
			users: parseUsers(rawUsers.users)
		}),
		pendingChanges: await hasPendingChanges(config)
	};
};
