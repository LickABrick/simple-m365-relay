<script lang="ts">
	import { onMount } from 'svelte';
	import { connectLiveStream, type LiveState } from '$lib/client/live-stream';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Alert from '$lib/components/ui/alert';
	import Activity from '@lucide/svelte/icons/activity';
	import ArrowRight from '@lucide/svelte/icons/arrow-right';
	import CircleAlert from '@lucide/svelte/icons/circle-alert';
	import CircleCheck from '@lucide/svelte/icons/circle-check';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let live = $state({
		health: data.health,
		queue: data.queue,
		token: data.token,
		users: data.users
	});
	let streamState = $state<LiveState>('loading');
	onMount(() =>
		connectLiveStream<typeof live>({
			url: '/api/live',
			ondata: (next) => (live = next),
			onstate: (state) => (streamState = state)
		})
	);
	const queueCount = $derived(
		live.queue.includes('Mail queue is empty')
			? 0
			: (live.queue.match(/^[A-F0-9]{5,}/gm) || []).length
	);
</script>

<main class="console-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/relay/overview</p>
			<h1>System overview</h1>
			<p>Live readiness and mail-flow state for this relay.</p>
		</div>
		<Badge variant={streamState === 'live' ? 'secondary' : 'outline'}
			><Activity />{streamState === 'live'
				? 'Live'
				: streamState === 'paused'
					? 'Paused'
					: streamState === 'loading'
						? 'Connecting'
						: 'Retrying'}</Badge
		>
	</header>
	{#if !data.configured}<Alert.Root
			><CircleAlert /><Alert.Title>Relay setup is incomplete</Alert.Title><Alert.Description
				>Finish Microsoft 365 and relay configuration before relying on delivery.</Alert.Description
			><Alert.Action
				><Button href="/onboarding" size="sm"
					>Continue setup<ArrowRight data-icon="inline-end" /></Button
				></Alert.Action
			></Alert.Root
		>{/if}
	{#if data.update.updateAvailable}<Alert.Root
			><CircleAlert /><Alert.Title>Stable update available: {data.update.latestVersion}</Alert.Title
			><Alert.Description
				>Running {data.update.currentVersion}. Review the release before updating the containers.</Alert.Description
			><Alert.Action
				><Button href={data.update.url} target="_blank" rel="noreferrer" size="sm" variant="outline"
					>View release</Button
				></Alert.Action
			></Alert.Root
		>{/if}
	<section class="telemetry-grid" aria-label="Live relay status">
		<Card.Root
			><Card.Header
				><Card.Description>RELAY PROCESS</Card.Description><Card.Title
					>{live.health ? 'ONLINE' : 'OFFLINE'}</Card.Title
				></Card.Header
			><Card.Content
				>{#if live.health}<Badge><CircleCheck />Responding</Badge>{:else}<Badge
						variant="destructive">Control unavailable</Badge
					>{/if}</Card.Content
			></Card.Root
		>
		<Card.Root
			><Card.Header
				><Card.Description>QUEUE DEPTH</Card.Description><Card.Title>{queueCount}</Card.Title
				></Card.Header
			><Card.Content><span class="telemetry-note">messages awaiting delivery</span></Card.Content
			></Card.Root
		>
		<Card.Root
			><Card.Header
				><Card.Description>OAUTH CREDENTIAL</Card.Description><Card.Title
					>{live.token['ok'] === true ? 'DETECTED' : 'MISSING'}</Card.Title
				></Card.Header
			><Card.Content
				><Button href="/microsoft" variant="outline" size="sm">Inspect token</Button></Card.Content
			></Card.Root
		>
		<Card.Root
			><Card.Header
				><Card.Description>SMTP CLIENTS</Card.Description><Card.Title
					>{live.users.length}</Card.Title
				></Card.Header
			><Card.Content
				><Button href="/clients" variant="outline" size="sm">Manage access</Button></Card.Content
			></Card.Root
		>
	</section>
	<section class="route-grid">
		<a href="/activity"
			><span>01</span>
			<div><strong>Live activity</strong><small>Stream queue and mail-log changes</small></div>
			<ArrowRight /></a
		>
		<a href="/settings/relay"
			><span>02</span>
			<div>
				<strong>Relay configuration</strong><small
					>{data.pending
						? 'Saved changes are waiting to be applied'
						: 'Running configuration is synchronized'}</small
				>
			</div>
			<ArrowRight /></a
		>
		<a href="/delivery"
			><span>03</span>
			<div><strong>Delivery probe</strong><small>Submit and verify a message path</small></div>
			<ArrowRight /></a
		>
		<a href="/recovery"
			><span>04</span>
			<div><strong>Recovery</strong><small>Backups and redacted diagnostics</small></div>
			<ArrowRight /></a
		>
	</section>
</main>
