<script lang="ts">
	import { onMount } from 'svelte';
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { microsoftSettingsSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { progressive } from '$lib/actions/progressive';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { toast } from 'svelte-sonner';
	import Refresh from '@lucide/svelte/icons/refresh-cw';
	import Key from '@lucide/svelte/icons/key-round';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let token = $state(data.token),
		deviceLog = $state(data.deviceLog),
		refreshLog = $state(data.refreshLog),
		connected = $state(false);
	// svelte-ignore state_referenced_locally
	const microsoft = superForm(data.microsoftForm, {
		validators: zod4Client(microsoftSettingsSchema),
		onResult: ({ result }) => {
			if (result.type === 'success') toast.success('Microsoft configuration saved.');
		}
	});
	const { form, enhance, submitting } = microsoft;
	onMount(() => {
		const events = new EventSource('/api/live?scope=microsoft');
		events.addEventListener('update', (event) => {
			const next = JSON.parse((event as MessageEvent).data);
			token = next.token;
			deviceLog = next.deviceLog;
			refreshLog = next.refreshLog;
			connected = true;
		});
		events.onerror = () => (connected = false);
		return () => events.close();
	});
</script>

<main class="console-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/microsoft/oauth</p>
			<h1>Microsoft OAuth</h1>
			<p>Configure the public-client application and maintain the credential used for XOAUTH2.</p>
		</div>
		<div class="action-row">
			<Badge variant={connected ? 'secondary' : 'outline'}
				>{connected ? 'LIVE' : 'RECONNECTING'}</Badge
			><Badge variant={Object.keys(token).length ? 'secondary' : 'destructive'}
				>{Object.keys(token).length ? 'TOKEN DETECTED' : 'TOKEN MISSING'}</Badge
			>
		</div>
	</header>
	<div class="two-panel">
		<Card.Root
			><Card.Header
				><Card.Title>Entra application</Card.Title><Card.Description
					>No client secret is stored or required.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/save" use:enhance>
					<input type="hidden" name="csrf" bind:value={$form.csrf} /><Field.FieldGroup
						><FormTextField
							form={microsoft}
							name="ms365_smtp_user"
							label="Licensed sending mailbox"
							type="email"
							bind:value={$form.ms365_smtp_user}
						/><FormTextField
							form={microsoft}
							name="tenant_id"
							label="Tenant ID"
							bind:value={$form.tenant_id}
						/><FormTextField
							form={microsoft}
							name="client_id"
							label="Application client ID"
							bind:value={$form.client_id}
						/><Field.Field
							><Field.FieldLabel for="refresh">Refresh interval (minutes)</Field.FieldLabel><Input
								id="refresh"
								name="auto_refresh_minutes"
								type="number"
								min="1"
								max="1440"
								bind:value={$form.auto_refresh_minutes}
							/></Field.Field
						><Button type="submit" disabled={$submitting}>Save Microsoft settings</Button
						></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		><Card.Root
			><Card.Header
				><Card.Title>Credential lifecycle</Card.Title><Card.Description
					>Device authorization runs inside the relay container.</Card.Description
				></Card.Header
			><Card.Content class="stack"
				><div class="action-row">
					<form method="POST" action="?/start" use:progressive>
						<input type="hidden" name="csrf" value={$form.csrf} /><Button type="submit"
							><Key data-icon="inline-start" />Start device flow</Button
						>
					</form>
					<form method="POST" action="?/refresh" use:progressive>
						<input type="hidden" name="csrf" value={$form.csrf} /><Button
							type="submit"
							variant="outline"><Refresh data-icon="inline-start" />Refresh now</Button
						>
					</form>
				</div>
				<div>
					<p class="terminal-label">TOKEN STATUS</p>
					<pre aria-live="polite">{JSON.stringify(token, null, 2) ||
							'No token status available.'}</pre>
				</div>
				<div>
					<p class="terminal-label">DEVICE FLOW</p>
					<pre aria-live="polite">{deviceLog || 'Device flow has not started.'}</pre>
				</div>
				<div>
					<p class="terminal-label">REFRESH LOG</p>
					<pre aria-live="polite">{refreshLog || 'No refresh events recorded.'}</pre>
				</div></Card.Content
			></Card.Root
		>
	</div>
</main>
