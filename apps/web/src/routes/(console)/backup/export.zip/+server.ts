import { control } from '$lib/server/control';
import type { RequestHandler } from './$types';
export const GET: RequestHandler = async ({ locals }) => {
	if (!locals.user) return new Response('Unauthorized', { status: 401 });
	const result = await control<{ zip_b64: string }>('/backup/export');
	return new Response(Buffer.from(result.zip_b64, 'base64'), {
		headers: {
			'Content-Type': 'application/zip',
			'Content-Disposition': 'attachment; filename="simple-m365-relay-backup.zip"',
			'Cache-Control': 'no-store'
		}
	});
};
