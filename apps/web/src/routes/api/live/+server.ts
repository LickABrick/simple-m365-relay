import {
	getActivity,
	getConsoleStatus,
	getMicrosoftState,
	getOverview,
	getRelayHealth
} from '$lib/server/operations';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = ({ request, url }) => {
	const encoder = new TextEncoder();
	let timer: ReturnType<typeof setTimeout>;
	let closed = false;
	const stream = new ReadableStream({
		async start(controller) {
			const enqueue = (event: string, payload: unknown) => {
				if (closed) return;
				try {
					controller.enqueue(
						encoder.encode(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`)
					);
				} catch {
					closed = true;
				}
			};
			const send = async () => {
				if (closed) return;
				try {
					const scope = url.searchParams.get('scope');
					const payload =
						scope === 'activity'
							? await getActivity()
							: scope === 'microsoft'
								? await getMicrosoftState()
								: scope === 'health'
									? await getRelayHealth()
									: scope === 'status'
										? await getConsoleStatus()
										: await getOverview();
					enqueue('update', payload);
				} catch (error) {
					enqueue('fault', {
						message: error instanceof Error ? error.message : 'Live update failed'
					});
				}
				if (!closed) timer = setTimeout(send, 3000);
			};
			request.signal.addEventListener('abort', () => {
				closed = true;
				clearTimeout(timer);
				try {
					controller.close();
				} catch {
					/* already closed */
				}
			});
			await send();
		},
		cancel() {
			closed = true;
			clearTimeout(timer);
		}
	});
	return new Response(stream, {
		headers: {
			'Content-Type': 'text/event-stream',
			'Cache-Control': 'no-cache, no-transform',
			Connection: 'keep-alive',
			'X-Accel-Buffering': 'no'
		}
	});
};
