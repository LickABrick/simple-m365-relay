import { hasPendingChanges, loadConfig } from '$lib/server/config';
import { getOverview } from '$lib/server/operations';
import { evaluateReadiness } from '$lib/server/readiness';
import { getUpdateStatus } from '$lib/server/updates';
import type { PageServerLoad } from './$types';
import { analyzeOAuthCapabilities } from '$lib/oauth-capabilities';

export const load: PageServerLoad = async () => {
	const [overview, config, update] = await Promise.all([
		getOverview(),
		loadConfig(),
		getUpdateStatus()
	]);
	const capabilities = analyzeOAuthCapabilities(config, overview.token);
	return {
		...overview,
		config,
		update,
		pending: await hasPendingChanges(config),
		capabilities,
		readiness: evaluateReadiness(config, {
			tokenPresent: overview.token['ok'] === true,
			tokenReady: capabilities.tokenReady,
			users: overview.users
		})
	};
};
