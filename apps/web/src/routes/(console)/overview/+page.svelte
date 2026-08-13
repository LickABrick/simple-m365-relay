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
	import Check from '@lucide/svelte/icons/check';
	import { analyzeOAuthCapabilities } from '$lib/oauth-capabilities';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let live = $state({
		health: data.health,
		queue: data.queue,
		problems: data.problems,
		token: data.token,
		users: data.users
	});
	let streamState = $state<LiveState>('loading');
	let acknowledgedProblems = $state<string[]>([]);
	const problemKey = (problem: (typeof live.problems)[number]) =>
		JSON.stringify([problem.source, problem.severity, problem.context, problem.message]);
	const newProblems = $derived(
		live.problems.filter((problem) => !acknowledgedProblems.includes(problemKey(problem)))
	);
	const acknowledgeProblems = () => {
		acknowledgedProblems = live.problems.map(problemKey);
		localStorage.setItem('sm365r.acknowledged-problems', JSON.stringify(acknowledgedProblems));
	};
	onMount(() => {
		try {
			acknowledgedProblems = JSON.parse(
				localStorage.getItem('sm365r.acknowledged-problems') || '[]'
			);
		} catch {
			acknowledgedProblems = [];
		}
		return connectLiveStream<typeof live>({
			url: '/api/live',
			ondata: (next) => (live = next),
			onstate: (state) => (streamState = state)
		});
	});
	const queueCount = $derived(
		live.queue.includes('Mail queue is empty')
			? 0
			: (live.queue.match(/^[A-F0-9]{5,}/gm) || []).length
	);
	const capabilities = $derived(analyzeOAuthCapabilities(data.config, live.token));
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
	{#if !data.readiness.complete}<Alert.Root
			><CircleAlert /><Alert.Title>Relay setup is incomplete</Alert.Title><Alert.Description
				>{data.readiness.incomplete.length} required {data.readiness.incomplete.length === 1
					? 'step remains'
					: 'steps remain'}: {data.readiness.incomplete
					.map((check) => check.label)
					.join(', ')}.</Alert.Description
			><Alert.Action
				><Button href={data.readiness.nextHref} size="sm"
					>Continue setup<ArrowRight data-icon="inline-end" /></Button
				></Alert.Action
			></Alert.Root
		>{/if}
	{#if capabilities.tokenPresent && !capabilities.tokenReady}<Alert.Root variant="destructive"
			><CircleAlert /><Alert.Title>OAuth credential cannot safely submit mail</Alert.Title
			><Alert.Description
				>{capabilities.configurationIssue ||
					capabilities.tokenIssues[0]?.message ||
					'The token is missing a required SMTP capability.'}</Alert.Description
			><Alert.Action
				><Button href="/microsoft" size="sm" variant="outline"
					>Review authorization<ArrowRight data-icon="inline-end" /></Button
				></Alert.Action
			></Alert.Root
		>{/if}
	{#if capabilities.tokenReady && capabilities.identityMismatch}<Alert.Root
			><CircleAlert /><Alert.Title>Delegated mailbox rights need a delivery check</Alert.Title
			><Alert.Description
				>The token belongs to {live.token.identity}, while SMTP authenticates as {data.config
					.ms365_smtp_user}. Token inspection cannot verify Exchange mailbox or Send As assignments.</Alert.Description
			><Alert.Action
				><Button href="/delivery" size="sm" variant="outline"
					>Run delivery test<ArrowRight data-icon="inline-end" /></Button
				></Alert.Action
			></Alert.Root
		>{/if}
	{#if newProblems.length}<Alert.Root variant="destructive"
			><CircleAlert /><Alert.Title
				>{newProblems.length} new operational {newProblems.length === 1 ? 'problem' : 'problems'} detected</Alert.Title
			><Alert.Description>{newProblems[0].context}: {newProblems[0].message}</Alert.Description
			><Alert.Action
				><div class="action-row">
					<Button href="/activity?problems=1" size="sm" variant="outline"
						>Inspect activity<ArrowRight data-icon="inline-end" /></Button
					><Button type="button" size="sm" variant="outline" onclick={acknowledgeProblems}
						><Check data-icon="inline-start" />Acknowledge current</Button
					>
				</div></Alert.Action
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
					>{capabilities.tokenReady
						? 'READY'
						: capabilities.tokenPresent
							? 'ATTENTION'
							: 'MISSING'}</Card.Title
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
						: data.readiness.complete
							? 'Running configuration is synchronized'
							: 'Complete setup before relying on delivery'}</small
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
