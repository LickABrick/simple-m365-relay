import { control } from '$lib/server/control';
import { loadConfig, hasPendingChanges } from '$lib/server/config';
import type { RequestHandler } from './$types';

const safe = async <T>(value: Promise<T>, fallback: T) => {
	try {
		return await value;
	} catch {
		return fallback;
	}
};
export const GET: RequestHandler = async ({ locals }) => {
	if (!locals.user) return new Response('Unauthorized', { status: 401 });
	const config = await loadConfig();
	const [health, token, queue, log] = await Promise.all([
		safe(control('/health'), {}),
		safe(control('/token/status'), {}),
		safe(control<{ mailq: string }>('/mailq'), { mailq: '' }),
		safe(control<{ maillog: string }>('/maillog'), { maillog: '' })
	]);
	const redacted = {
		...config,
		oauth: {
			...config.oauth,
			tenant_id: config.oauth.tenant_id ? '[configured]' : '',
			client_id: config.oauth.client_id ? '[configured]' : ''
		}
	};
	return new Response(
		`# Simple M365 Relay diagnostics\nversion=${process.env.APP_VERSION || '2.0.0-rc.2'}\npending=${await hasPendingChanges(config)}\nhealth=${JSON.stringify(health)}\ntoken=${JSON.stringify(token)}\n\n## config\n${JSON.stringify(redacted, null, 2)}\n\n## queue\n${queue.mailq}\n\n## recent log\n${log.maillog}\n`,
		{
			headers: {
				'Content-Type': 'text/plain; charset=utf-8',
				'Cache-Control': 'no-store',
				'Content-Disposition': 'attachment; filename="simple-m365-relay-diagnostics.txt"'
			}
		}
	);
};
