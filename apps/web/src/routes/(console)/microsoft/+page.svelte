<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { connectLiveStream, type LiveState } from '$lib/client/live-stream';
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { microsoftSettingsSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import ProgressiveForm from '$lib/components/progressive-form.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import { Spinner } from '$lib/components/ui/spinner';
	import { toast } from 'svelte-sonner';
	import Refresh from '@lucide/svelte/icons/refresh-cw';
	import Key from '@lucide/svelte/icons/key-round';
	import { relayState } from '$lib/client/relay-state.svelte';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let token = $state(data.token),
		deviceLog = $state(data.deviceLog),
		refreshLog = $state(data.refreshLog),
		streamState = $state<LiveState>('loading');
	// svelte-ignore state_referenced_locally
	const microsoft = superForm(
		untrack(() => data.microsoftForm),
		{
			validators: zod4Client(microsoftSettingsSchema),
			applyAction: false,
			invalidateAll: false,
			onResult: ({ result }) => {
				if (result.type === 'success') {
					const saved = (result.data as { form?: { data?: (typeof data.microsoftForm)['data'] } })
						?.form?.data;
					if (saved) queueMicrotask(() => microsoft.reset({ data: saved, newState: saved }));
					toast.success('Microsoft configuration saved.');
				} else if (result.type === 'failure')
					toast.error(
						(result.data as { error?: string })?.error || 'Microsoft settings could not be saved.'
					);
			}
		}
	);
	const { form, enhance, submitting, tainted } = microsoft;
	const changed = $derived(microsoft.isTainted($tainted));
	const tokenPresent = $derived(token.ok === true);
	const microsoftConfigured = $derived(
		Boolean($form.ms365_smtp_user && $form.tenant_id && $form.client_id)
	);
	onMount(() =>
		connectLiveStream<{ token: Record<string, unknown>; deviceLog: string; refreshLog: string }>({
			url: '/api/live?scope=microsoft',
			ondata: (next) => {
				token = next.token;
				deviceLog = next.deviceLog;
				refreshLog = next.refreshLog;
			},
			onstate: (state) => (streamState = state)
		})
	);
</script>

<main class="console-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/microsoft/oauth</p>
			<h1>Microsoft OAuth</h1>
			<p>Configure the public-client application and maintain the credential used for XOAUTH2.</p>
		</div>
		<div class="action-row">
			<Badge variant={streamState === 'live' ? 'secondary' : 'outline'}
				>{streamState === 'live'
					? 'LIVE'
					: streamState === 'paused'
						? 'PAUSED'
						: streamState === 'loading'
							? 'CONNECTING'
							: 'RETRYING'}</Badge
			><Badge variant={tokenPresent ? 'secondary' : 'destructive'}
				>{tokenPresent ? 'TOKEN DETECTED' : 'TOKEN MISSING'}</Badge
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
						/><FormTextField form={microsoft} name="tenant_id" label="Tenant ID" /><FormTextField
							form={microsoft}
							name="client_id"
							label="Application client ID"
						/><Field.Field
							><Field.FieldLabel for="refresh">Refresh interval (minutes)</Field.FieldLabel><Input
								id="refresh"
								name="auto_refresh_minutes"
								type="number"
								min="1"
								max="1440"
								bind:value={$form.auto_refresh_minutes}
							/></Field.Field
						><Button type="submit" disabled={$submitting || !changed}
							>{#if $submitting}<Spinner data-icon="inline-start" />{/if}{$submitting
								? 'Saving…'
								: 'Save Microsoft settings'}</Button
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
					<ProgressiveForm method="POST" action="?/start">
						{#snippet children(pending)}<input
								type="hidden"
								name="csrf"
								value={$form.csrf}
							/><Button
								type="submit"
								disabled={pending || !relayState.available || !microsoftConfigured}
								>{#if pending}<Spinner data-icon="inline-start" />{:else}<Key
										data-icon="inline-start"
									/>{/if}{pending ? 'Starting…' : 'Start device flow'}</Button
							>{/snippet}
					</ProgressiveForm>
					<ProgressiveForm method="POST" action="?/refresh">
						{#snippet children(pending)}<input
								type="hidden"
								name="csrf"
								value={$form.csrf}
							/><Button
								type="submit"
								disabled={pending || !relayState.available || !tokenPresent}
								variant="outline"
								>{#if pending}<Spinner data-icon="inline-start" />{:else}<Refresh
										data-icon="inline-start"
									/>{/if}{pending ? 'Refreshing…' : 'Refresh now'}</Button
							>{/snippet}
					</ProgressiveForm>
				</div>
				{#if !relayState.available}<p class="telemetry-note">
						Credential actions are unavailable while the relay is offline.
					</p>{:else if !microsoftConfigured}<p class="telemetry-note">
						Save the mailbox, tenant, and application ID before starting authorization.
					</p>{/if}
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
