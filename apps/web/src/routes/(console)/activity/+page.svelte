<script lang="ts">
	import { onMount } from 'svelte';
	import { connectLiveStream, type LiveState } from '$lib/client/live-stream';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import * as Field from '$lib/components/ui/field';
	import { Switch } from '$lib/components/ui/switch';
	import Radio from '@lucide/svelte/icons/radio';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let queue = $state(data.queue),
		logs = $state(data.logs),
		streamState = $state<LiveState>('loading'),
		query = $state(''),
		problemsOnly = $state(false);
	let filtered = $derived(
		logs
			.split('\n')
			.filter(
				(line) =>
					(!query || line.toLowerCase().includes(query.toLowerCase())) &&
					(!problemsOnly || /(warn|error|deferred|reject|fail)/i.test(line))
			)
			.join('\n')
	);
	onMount(() =>
		connectLiveStream<{ queue: string; logs: string }>({
			url: '/api/live?scope=activity',
			ondata: (next) => {
				queue = next.queue;
				logs = next.logs;
			},
			onstate: (state) => (streamState = state)
		})
	);
	const streamLabel = $derived(
		streamState === 'live'
			? 'STREAMING'
			: streamState === 'paused'
				? 'PAUSED'
				: streamState === 'loading'
					? 'CONNECTING'
					: 'RETRYING'
	);
</script>

<main class="console-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/operations/activity</p>
			<h1>Live activity</h1>
			<p>Queue and redacted mail-log output refresh automatically every three seconds.</p>
		</div>
		<Badge variant={streamState === 'live' ? 'secondary' : 'outline'}><Radio />{streamLabel}</Badge>
	</header>
	<Card.Root
		><Card.Header
			><Card.Title>Mail queue</Card.Title><Card.Description
				>Messages still owned by Postfix.</Card.Description
			></Card.Header
		><Card.Content><pre>{queue || 'Mail queue is empty.'}</pre></Card.Content></Card.Root
	><Card.Root
		><Card.Header
			><Card.Title>Mail log</Card.Title><Card.Description
				>Known token material is redacted by the relay control service.</Card.Description
			></Card.Header
		><Card.Content class="stack"
			><div class="log-toolbar">
				<Field.Field
					><Field.FieldLabel for="filter">Filter log</Field.FieldLabel><Input
						id="filter"
						placeholder="deferred, sasl, recipient…"
						bind:value={query}
					/></Field.Field
				><Field.Field orientation="horizontal"
					><Switch
						id="problems"
						bind:checked={problemsOnly}
						aria-label="Show problems only"
					/><Field.FieldLabel for="problems">Problems only</Field.FieldLabel></Field.Field
				>
			</div>
			<pre class="live-log" aria-live="polite">{filtered ||
					'No matching log entries.'}</pre></Card.Content
		></Card.Root
	>
</main>
