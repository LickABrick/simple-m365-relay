<script lang="ts">
	import { page } from '$app/state';
	import { enhance } from '$app/forms';
	import { Button, buttonVariants } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import { Separator } from '$lib/components/ui/separator';
	import { Spinner } from '$lib/components/ui/spinner';
	import { onMount } from 'svelte';
	import { connectLiveStream } from '$lib/client/live-stream';
	import { relayState } from '$lib/client/relay-state.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import CircleAlert from '@lucide/svelte/icons/circle-alert';
	import * as Sheet from '$lib/components/ui/sheet';
	import Activity from '@lucide/svelte/icons/activity';
	import ArchiveRestore from '@lucide/svelte/icons/archive-restore';
	import AtSign from '@lucide/svelte/icons/at-sign';
	import Gauge from '@lucide/svelte/icons/gauge';
	import KeyRound from '@lucide/svelte/icons/key-round';
	import Menu from '@lucide/svelte/icons/menu';
	import Network from '@lucide/svelte/icons/network';
	import Send from '@lucide/svelte/icons/send';
	import Settings from '@lucide/svelte/icons/settings';
	import Users from '@lucide/svelte/icons/users';
	import ArrowRight from '@lucide/svelte/icons/arrow-right';

	let { children, user, version, csrf, relayAvailable, readiness, pendingChanges } = $props();
	// svelte-ignore state_referenced_locally
	relayState.available = relayAvailable;
	// svelte-ignore state_referenced_locally
	let readinessState = $state(readiness);
	// svelte-ignore state_referenced_locally
	let hasPendingChanges = $state(pendingChanges);
	onMount(() =>
		connectLiveStream<{
			relayAvailable: boolean;
			readiness: typeof readiness;
			pendingChanges: boolean;
		}>({
			url: '/api/live?scope=status',
			ondata: (status) => {
				relayState.available = status.relayAvailable;
				readinessState = status.readiness;
				hasPendingChanges = status.pendingChanges;
				relayState.live = true;
			},
			onstate: (state) => (relayState.live = state === 'live')
		})
	);
	const groups = [
		{
			label: 'Operate',
			links: [
				{ href: '/overview', label: 'Overview', icon: Gauge },
				{ href: '/activity', label: 'Live activity', icon: Activity },
				{ href: '/delivery', label: 'Delivery test', icon: Send }
			]
		},
		{
			label: 'Configure',
			links: [
				{ href: '/settings/relay', label: 'Relay settings', icon: Settings },
				{ href: '/settings/network', label: 'Network & TLS', icon: Network },
				{ href: '/clients', label: 'SMTP clients', icon: Users },
				{ href: '/senders', label: 'Sender policy', icon: AtSign },
				{ href: '/microsoft', label: 'Microsoft OAuth', icon: KeyRound }
			]
		},
		{
			label: 'System',
			links: [{ href: '/recovery', label: 'Recovery', icon: ArchiveRestore }]
		}
	];
	const active = (href: string) =>
		page.url.pathname === href || page.url.pathname.startsWith(`${href}/`);
	let mobileOpen = $state(false);
	let signingOut = $state(false);
	const enhanceLogout = (node: HTMLFormElement) =>
		enhance(node, () => {
			signingOut = true;
			return async ({ update }) => {
				await update({ invalidateAll: false });
				signingOut = false;
			};
		});
</script>

{#snippet navigation()}
	<div class="brand-lockup">
		<span class="brand-glyph" aria-hidden="true">M/</span>
		<div><strong>Simple M365 Relay</strong><small>CONTROL PLANE · {version}</small></div>
	</div>
	<Separator />
	{#if !readinessState.complete || hasPendingChanges}
		<div class="nav-status" aria-label="Relay attention required">
			{#if !readinessState.complete}
				<Alert.Root>
					<CircleAlert />
					<Alert.Title>Setup incomplete</Alert.Title>
					<Alert.Description
						>{readinessState.incomplete.length} required {readinessState.incomplete.length === 1
							? 'step'
							: 'steps'} remaining.</Alert.Description
					>
					<Alert.Action
						><Button href={readinessState.nextHref} size="sm" onclick={() => (mobileOpen = false)}
							>Continue<ArrowRight data-icon="inline-end" /></Button
						></Alert.Action
					>
				</Alert.Root>
			{/if}
			{#if hasPendingChanges}
				<Alert.Root>
					<CircleAlert />
					<Alert.Title>Changes not applied</Alert.Title>
					<Alert.Description>Saved settings differ from the running relay.</Alert.Description>
					<Alert.Action
						><Button
							href="/settings/relay"
							size="sm"
							variant="outline"
							onclick={() => (mobileOpen = false)}>Review changes</Button
						></Alert.Action
					>
				</Alert.Root>
			{/if}
		</div>
	{/if}
	<nav aria-label="Control plane">
		{#each groups as group}
			<div class="nav-group">
				<p>{group.label}</p>
				{#each group.links as link}
					<a
						href={link.href}
						aria-current={active(link.href) ? 'page' : undefined}
						onclick={() => (mobileOpen = false)}
					>
						<link.icon /><span>{link.label}</span
						>{#if hasPendingChanges && link.href === '/settings/relay'}<Badge variant="secondary"
								>UNAPPLIED</Badge
							>{/if}
					</a>
				{/each}
			</div>
		{/each}
	</nav>
	<div class="nav-session">
		<div><span>SESSION</span><strong>{user}</strong></div>
		<form method="POST" action="/logout" use:enhanceLogout>
			<input type="hidden" name="csrf" value={csrf} />
			<Button type="submit" variant="outline" size="sm" disabled={signingOut}
				>{#if signingOut}<Spinner data-icon="inline-start" />{/if}{signingOut
					? 'Signing out…'
					: 'Sign out'}</Button
			>
		</form>
	</div>
{/snippet}

<div class="console-shell" data-sveltekit-preload-data="hover">
	<aside class="console-rail">{@render navigation()}</aside>
	<div class="console-main">
		<header class="mobile-console-header">
			<Sheet.Root bind:open={mobileOpen}>
				<Sheet.Trigger
					class={buttonVariants({ variant: 'outline', size: 'icon' })}
					aria-label="Open navigation"><Menu /></Sheet.Trigger
				>
				<Sheet.Content side="left">
					<Sheet.Header
						><Sheet.Title>Control plane</Sheet.Title><Sheet.Description
							>Relay operations and configuration</Sheet.Description
						></Sheet.Header
					>
					<div class="mobile-console-nav">{@render navigation()}</div>
				</Sheet.Content>
			</Sheet.Root>
			<strong>SM365 / CONTROL</strong>
		</header>
		{#if !relayState.available}
			<div class="service-banner" aria-live="polite">
				<Alert.Root variant="destructive"
					><CircleAlert /><Alert.Title>Relay service unavailable</Alert.Title><Alert.Description
						>Configuration can still be edited, but mail, credential, OAuth, validation, apply,
						reload, backup, and diagnostics operations are unavailable until connectivity returns.</Alert.Description
					></Alert.Root
				>
			</div>
		{/if}
		{@render children()}
	</div>
</div>
