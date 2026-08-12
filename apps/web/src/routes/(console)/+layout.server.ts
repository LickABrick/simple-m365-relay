import type { LayoutServerLoad } from './$types';
import { control } from '$lib/server/control';

export const load: LayoutServerLoad = async ({ locals }) => {
	const relayAvailable = await control<{ ok: boolean }>('/health')
		.then((value) => value.ok)
		.catch(() => false);
	return {
		user: locals.user,
		csrf: locals.csrf,
		version: process.env.APP_VERSION || '2.0.0-rc.1',
		relayAvailable
	};
};
