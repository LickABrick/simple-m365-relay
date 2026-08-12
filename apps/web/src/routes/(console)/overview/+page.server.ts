import { hasPendingChanges, loadConfig } from '$lib/server/config';
import { getOverview } from '$lib/server/operations';
import { evaluateReadiness } from '$lib/server/readiness';
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
		readiness: evaluateReadiness(config, {
			tokenPresent: overview.token['ok'] === true,
			users: overview.users
		})
	};
};
