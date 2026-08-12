<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Separator } from '$lib/components/ui/separator';
	import * as Sheet from '$lib/components/ui/sheet';
	import Menu from '@lucide/svelte/icons/menu';
	import Activity from '@lucide/svelte/icons/activity';
	import Settings from '@lucide/svelte/icons/settings';
	import Users from '@lucide/svelte/icons/users';
	import KeyRound from '@lucide/svelte/icons/key-round';
	import ScrollText from '@lucide/svelte/icons/scroll-text';
	import Send from '@lucide/svelte/icons/send';
	import AtSign from '@lucide/svelte/icons/at-sign';
	import ArchiveRestore from '@lucide/svelte/icons/archive-restore';
	let { children, csrf, user, version } = $props();
	const links = [
		{ href: '#overview', label: 'Overview', icon: Activity },
		{ href: '#configuration', label: 'Configuration', icon: Settings },
		{ href: '#clients', label: 'SMTP clients', icon: Users },
		{ href: '#senders', label: 'Sender policy', icon: AtSign },
		{ href: '#oauth', label: 'Microsoft OAuth', icon: KeyRound },
		{ href: '#delivery', label: 'Delivery test', icon: Send },
		{ href: '#recovery', label: 'Recovery', icon: ArchiveRestore },
		{ href: '#logs', label: 'Logs', icon: ScrollText }
	];
</script>

{#snippet navigation()}
	<div class="brand">
		<span class="brand-mark" aria-hidden="true">M</span>
		<div><strong>Simple M365 Relay</strong><small>Control plane</small></div>
	</div>
	<Separator />
	<nav aria-label="Operations">
		{#each links as link}<a href={link.href}><link.icon /><span>{link.label}</span></a>{/each}
	</nav>
	<div class="nav-footer">
		<span>{user}</span><small>v{version}</small>
		<form method="POST" action="?/logout">
			<input type="hidden" name="csrf" value={csrf} /><Button
				type="submit"
				variant="outline"
				size="sm">Sign out</Button
			>
		</form>
	</div>
{/snippet}
<div class="app-shell">
	<aside class="desktop-nav">{@render navigation()}</aside>
	<div class="app-main">
		<header class="mobile-header">
			<Sheet.Root
				><Sheet.Trigger
					><Button variant="outline" size="icon" aria-label="Open navigation"><Menu /></Button
					></Sheet.Trigger
				><Sheet.Content side="left"
					><Sheet.Header
						><Sheet.Title class="sr-only">Navigation</Sheet.Title><Sheet.Description class="sr-only"
							>Relay administration sections</Sheet.Description
						></Sheet.Header
					>
					<div class="mobile-nav">{@render navigation()}</div></Sheet.Content
				></Sheet.Root
			><strong>Simple M365 Relay</strong>
		</header>
		{@render children()}
	</div>
</div>
