<script lang="ts">
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { connectLiveStream, type LiveState } from '$lib/client/live-stream';
	import { parseLog, parseQueue } from '$lib/activity';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import { Input } from '$lib/components/ui/input';
	import * as Field from '$lib/components/ui/field';
	import * as Table from '$lib/components/ui/table';
	import { Switch } from '$lib/components/ui/switch';
	import Radio from '@lucide/svelte/icons/radio';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let queue = $state(data.queue),
		logs = $state(data.logs),
		streamState = $state<LiveState>('loading'),
		query = $state(''),
		problemsOnly = $state(page.url.searchParams.get('problems') === '1');
	let queueEntries = $derived(parseQueue(queue));
	let filtered = $derived(
		parseLog(logs).filter(
			(entry) =>
				(!query ||
					`${entry.service} ${entry.message}`.toLowerCase().includes(query.toLowerCase())) &&
				(!problemsOnly || entry.severity !== 'info')
		)
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
	<Card.Root>
		<Card.Header>
			<Card.Title>Mail queue</Card.Title>
			<Card.Description>Messages still owned by Postfix.</Card.Description>
		</Card.Header>
		<Card.Content>
			{#if queueEntries.length}
				<Table.Root>
					<Table.Header
						><Table.Row
							><Table.Head>Queue ID</Table.Head><Table.Head>Route</Table.Head><Table.Head
								>Status</Table.Head
							><Table.Head>Age / size</Table.Head></Table.Row
						></Table.Header
					>
					<Table.Body>
						{#each queueEntries as entry}
							<Table.Row>
								<Table.Cell class="font-mono">{entry.id}</Table.Cell>
								<Table.Cell
									><div class="queue-route">
										<strong>{entry.sender}</strong><span
											>→ {entry.recipients.join(', ') || 'Recipient pending'}</span
										>
									</div></Table.Cell
								>
								<Table.Cell
									><div class="queue-status">
										<Badge variant={entry.reason ? 'destructive' : 'secondary'}
											>{entry.reason ? 'DEFERRED' : 'QUEUED'}</Badge
										>{#if entry.reason}<span>{entry.reason}</span>{/if}
									</div></Table.Cell
								>
								<Table.Cell
									><span class="queue-meta"
										>{entry.arrival}<br />{entry.size.toLocaleString()} bytes</span
									></Table.Cell
								>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			{:else}
				<p class="empty-log">Mail queue is empty.</p>
			{/if}
		</Card.Content>
	</Card.Root>
	<Card.Root>
		<Card.Header>
			<Card.Title>Mail log</Card.Title>
			<Card.Description
				>Known token material is redacted by the relay control service.</Card.Description
			>
		</Card.Header>
		<Card.Content class="stack">
			<div class="log-toolbar">
				<Field.Field>
					<Field.FieldLabel for="filter">Filter log</Field.FieldLabel>
					<Input id="filter" placeholder="deferred, sasl, recipient…" bind:value={query} />
				</Field.Field>
				<Field.Field orientation="horizontal">
					<Switch id="problems" bind:checked={problemsOnly} aria-label="Show problems only" />
					<Field.FieldLabel for="problems">Problems only</Field.FieldLabel>
				</Field.Field>
			</div>
			<div class="log-feed" aria-live="polite">
				{#each filtered as entry}
					<article class="log-entry" data-severity={entry.severity}>
						<div>
							<Badge
								variant={entry.severity === 'error'
									? 'destructive'
									: entry.severity === 'warning'
										? 'secondary'
										: 'outline'}>{entry.severity.toUpperCase()}</Badge
							><span class="log-time">{entry.time || '—'}</span><strong>{entry.service}</strong>
						</div>
						<p>{entry.message}</p>
					</article>
				{:else}
					<p class="empty-log">No matching log entries.</p>
				{/each}
			</div>
		</Card.Content>
	</Card.Root>
</main>
