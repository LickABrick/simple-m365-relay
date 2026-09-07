import { fail } from '@sveltejs/kit';
import { control } from '$lib/server/control';
import { errorMessage, reloadAction, requireCsrf } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = () => ({});
export const actions: Actions = {
	reload: reloadAction,
	import: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			const file = form.get('backup');
			if (!(file instanceof File) || !file.size) throw new Error('Choose a backup ZIP.');
			if (file.size > 10 * 1024 * 1024) throw new Error('Backup must be 10 MB or smaller.');
			await control('/backup/import', {
				zip_b64: Buffer.from(await file.arrayBuffer()).toString('base64')
			});
			return {
				success: true,
				message: 'Backup imported. Review and apply the restored configuration.'
			};
		} catch (error) {
			return fail(400, { error: errorMessage(error, 'Backup import failed.') });
		}
	}
};
