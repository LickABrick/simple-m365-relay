import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ locals }) => ({
	user: locals.user,
	csrf: locals.csrf,
	version: process.env.APP_VERSION || '2.0.0-rc.1'
});
