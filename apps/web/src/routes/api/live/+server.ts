import { getActivity, getMicrosoftState, getOverview } from '$lib/server/operations';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = ({ request, url }) => {
	const encoder = new TextEncoder();
	let timer: ReturnType<typeof setTimeout>;
	let closed = false;
	const stream = new ReadableStream({
		async start(controller) {
			const send = async () => {
				if (closed) return;
				try {
					const scope = url.searchParams.get('scope');
					const payload =
						scope === 'activity'
							? await getActivity()
							: scope === 'microsoft'
								? await getMicrosoftState()
								: await getOverview();
					controller.enqueue(encoder.encode(`event: update\ndata: ${JSON.stringify(payload)}\n\n`));
				} catch (error) {
					controller.enqueue(
						encoder.encode(
							`event: fault\ndata: ${JSON.stringify({ message: error instanceof Error ? error.message : 'Live update failed' })}\n\n`
						)
					);
				}
				timer = setTimeout(send, 3000);
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
