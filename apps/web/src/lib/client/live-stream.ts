import { toast } from 'svelte-sonner';

export type LiveState = 'loading' | 'live' | 'retrying' | 'paused';

export function connectLiveStream<T>({
	url,
	ondata,
	onstate
}: {
	url: string;
	ondata: (data: T) => void;
	onstate: (state: LiveState) => void;
}): () => void {
	let source: EventSource | undefined;
	let generation = 0;
	let connectedOnce = false;
	let announcedFailure = false;

	const close = () => {
		generation += 1;
		source?.close();
		source = undefined;
	};
	const open = () => {
		close();
		const current = generation;
		onstate(connectedOnce ? 'retrying' : 'loading');
		source = new EventSource(url);
		source.addEventListener('update', (event) => {
			if (current !== generation) return;
			try {
				ondata(JSON.parse((event as MessageEvent<string>).data) as T);
				onstate('live');
				if (announcedFailure) toast.success('Live connection restored.');
				connectedOnce = true;
				announcedFailure = false;
			} catch {
				onstate('retrying');
			}
		});
		source.addEventListener('fault', () => onstate('retrying'));
		source.onerror = () => {
			if (current !== generation) return;
			onstate('retrying');
			if (connectedOnce && !announcedFailure) {
				toast.error('Live connection interrupted. Retrying in the background.');
				announcedFailure = true;
			}
		};
	};
	const visibility = () => {
		if (document.hidden) {
			close();
			onstate('paused');
		} else open();
	};
	document.addEventListener('visibilitychange', visibility);
	visibility();
	return () => {
		document.removeEventListener('visibilitychange', visibility);
		close();
	};
}
