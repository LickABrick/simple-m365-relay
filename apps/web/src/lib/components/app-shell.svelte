<script lang="ts">
	import { page } from '$app/state';
	import { Button } from '$lib/components/ui/button';
	import { Separator } from '$lib/components/ui/separator';
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

	let { children, user, version, csrf } = $props();
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
</script>

{#snippet navigation()}
	<div class="brand-lockup">
		<span class="brand-glyph" aria-hidden="true">M/</span>
		<div><strong>Simple M365 Relay</strong><small>CONTROL PLANE · {version}</small></div>
	</div>
	<Separator />
	<nav aria-label="Control plane">
		{#each groups as group}
			<div class="nav-group">
				<p>{group.label}</p>
				{#each group.links as link}
					<a href={link.href} aria-current={active(link.href) ? 'page' : undefined}>
						<link.icon /><span>{link.label}</span>
					</a>
				{/each}
			</div>
		{/each}
	</nav>
	<div class="nav-session">
		<div><span>SESSION</span><strong>{user}</strong></div>
		<form method="POST" action="/logout">
			<input type="hidden" name="csrf" value={csrf} />
			<Button type="submit" variant="outline" size="sm">Sign out</Button>
		</form>
	</div>
{/snippet}

<div class="console-shell">
	<aside class="console-rail">{@render navigation()}</aside>
	<div class="console-main">
		<header class="mobile-console-header">
			<Sheet.Root>
				<Sheet.Trigger
					><Button variant="outline" size="icon" aria-label="Open navigation"><Menu /></Button
					></Sheet.Trigger
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
		{@render children()}
	</div>
</div>
