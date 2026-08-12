import { hasPendingChanges, loadConfig } from '$lib/server/config';
import { getOverview } from '$lib/server/operations';
import { getUpdateStatus } from '$lib/server/updates';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async () => {
	const [overview, config, update] = await Promise.all([
		getOverview(),
		loadConfig(),
		getUpdateStatus()
	]);
	return {
		...overview,
		update,
		pending: await hasPendingChanges(config),
		configured: Boolean(config.oauth.tenant_id && config.oauth.client_id && config.ms365_smtp_user)
	};
};
