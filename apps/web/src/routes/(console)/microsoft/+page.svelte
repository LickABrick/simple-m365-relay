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
	import * as Alert from '$lib/components/ui/alert';
	import * as Table from '$lib/components/ui/table';
	import { toast } from 'svelte-sonner';
	import Refresh from '@lucide/svelte/icons/refresh-cw';
	import Key from '@lucide/svelte/icons/key-round';
	import { relayState } from '$lib/client/relay-state.svelte';
	import { analyzeOAuthCapabilities, type TokenStatus } from '$lib/oauth-capabilities';
	import CircleAlert from '@lucide/svelte/icons/circle-alert';
	import CircleCheck from '@lucide/svelte/icons/circle-check';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let token = $state(data.token),
		deviceLog = $state(data.deviceLog),
		refreshLog = $state(data.refreshLog),
		streamState = $state<LiveState>('loading');
	let deviceFlowStarting = $state(false);
	let deviceFlowLog: HTMLDivElement;
	let deviceLogAtStart = $state('');
	let refreshRequested = $state(false);
	let refreshLogAtStart = $state('');
	const deviceFlowWaiting = $derived(deviceFlowStarting && deviceLog === deviceLogAtStart);
	const startConfirmed = () => {
		deviceLogAtStart = deviceLog;
		deviceFlowStarting = true;
		queueMicrotask(() => deviceFlowLog?.scrollIntoView({ behavior: 'smooth', block: 'center' }));
	};
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
	const capabilities = $derived(
		analyzeOAuthCapabilities(
			{
				...data.config,
				ms365_smtp_user: $form.ms365_smtp_user,
				oauth: {
					tenant_id: $form.tenant_id,
					client_id: $form.client_id,
					auto_refresh_minutes: $form.auto_refresh_minutes
				}
			},
			token as TokenStatus
		)
	);
	const tokenPresent = $derived(capabilities.tokenPresent);
	const microsoftConfigured = $derived(
		Boolean($form.ms365_smtp_user && $form.tenant_id && $form.client_id)
	);
	onMount(() =>
		connectLiveStream<{ token: Record<string, unknown>; deviceLog: string; refreshLog: string }>({
			url: '/api/live?scope=microsoft',
			ondata: (next) => {
				if (deviceFlowStarting && next.deviceLog !== deviceLogAtStart) deviceFlowStarting = false;
				if (refreshRequested && next.refreshLog !== refreshLogAtStart) refreshRequested = false;
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
			><Badge variant={capabilities.tokenReady ? 'secondary' : 'destructive'}
				>{capabilities.tokenReady
					? 'SMTP AUTH READY'
					: tokenPresent
						? 'TOKEN NEEDS ATTENTION'
						: 'TOKEN MISSING'}</Badge
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
				>{#if capabilities.configurationIssue}
					<Alert.Root variant="destructive">
						<CircleAlert />
						<Alert.Title>Token does not match the saved application</Alert.Title>
						<Alert.Description>{capabilities.configurationIssue}</Alert.Description>
					</Alert.Root>
				{/if}
				{#if capabilities.identityMismatch}
					<Alert.Root>
						<CircleAlert />
						<Alert.Title>Delegated mailbox permissions require verification</Alert.Title>
						<Alert.Description
							>The token belongs to {token.identity}, while SMTP authenticates as {$form.ms365_smtp_user}.
							This can be valid for delegated or shared mailbox access, but the token user needs the
							required Exchange mailbox and Send As rights. Confirm with a delivery test.</Alert.Description
						>
					</Alert.Root>
				{/if}
				{#each token.issues || [] as issue}
					<Alert.Root variant={issue.severity === 'error' ? 'destructive' : 'default'}>
						<CircleAlert />
						<Alert.Title
							>{issue.severity === 'error'
								? 'Authorization incomplete'
								: 'Authorization warning'}</Alert.Title
						>
						<Alert.Description>{issue.message}</Alert.Description>
					</Alert.Root>
				{/each}
				<div class="action-row">
					<ProgressiveForm method="POST" action="?/start" onsucceeded={startConfirmed}>
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
					<ProgressiveForm
						method="POST"
						action="?/refresh"
						onsucceeded={() => {
							refreshLogAtStart = refreshLog;
							refreshRequested = true;
						}}
					>
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
				{#if deviceFlowWaiting}
					<Alert.Root>
						<Spinner />
						<Alert.Title>Device flow started</Alert.Title>
						<Alert.Description
							>Waiting for Microsoft to return the sign-in URL and device code. This panel updates
							automatically.</Alert.Description
						>
					</Alert.Root>
				{:else if refreshRequested}
					<Alert.Root>
						<Spinner />
						<Alert.Title>Refresh requested</Alert.Title>
						<Alert.Description
							>Waiting for the relay to report the refreshed credential state.</Alert.Description
						>
					</Alert.Root>
				{/if}
				{#if !relayState.available}<p class="telemetry-note">
						Credential actions are unavailable while the relay is offline.
					</p>{:else if !microsoftConfigured}<p class="telemetry-note">
						Save the mailbox, tenant, and application ID before starting authorization.
					</p>{/if}
				<div>
					<p class="terminal-label">TOKEN CAPABILITIES</p>
					<Table.Root>
						<Table.Body>
							<Table.Row
								><Table.Cell>Credential</Table.Cell><Table.Cell
									>{tokenPresent ? 'Detected' : 'Missing'}</Table.Cell
								></Table.Row
							>
							<Table.Row
								><Table.Cell>Flow</Table.Cell><Table.Cell
									>{token.token_type || 'Unknown'}</Table.Cell
								></Table.Row
							>
							<Table.Row
								><Table.Cell>Authenticated identity</Table.Cell><Table.Cell
									>{token.identity || 'Not reported'}</Table.Cell
								></Table.Row
							>
							<Table.Row
								><Table.Cell>Exchange audience</Table.Cell><Table.Cell
									>{token.audience_ok === true
										? 'Valid'
										: token.audience_ok === false
											? 'Wrong resource'
											: 'Not reported'}</Table.Cell
								></Table.Row
							>
							<Table.Row
								><Table.Cell>SMTP.Send</Table.Cell><Table.Cell
									>{token.smtp_scope_granted === true
										? 'Granted'
										: token.smtp_scope_granted === false
											? 'Missing'
											: 'Could not inspect'}</Table.Cell
								></Table.Row
							>
							<Table.Row
								><Table.Cell>Offline refresh</Table.Cell><Table.Cell
									>{token.has_refresh_token ? 'Available' : 'Missing'}</Table.Cell
								></Table.Row
							>
						</Table.Body>
					</Table.Root>
				</div>
				<Alert.Root>
					<CircleCheck />
					<Alert.Title>Required Entra configuration</Alert.Title>
					<Alert.Description
						>Register a public client, enable device code flow, and grant the delegated Office 365
						Exchange Online SMTP.Send permission. Device authorization also requests offline_access
						for refresh tokens. Send As rights for additional sender addresses are configured
						separately in Exchange.</Alert.Description
					>
				</Alert.Root>
				<div bind:this={deviceFlowLog}>
					<p class="terminal-label">DEVICE FLOW</p>
					<pre aria-live="polite">{deviceLog ||
							(streamState === 'loading'
								? 'Loading the latest device-flow log…'
								: 'Device flow has not started.')}</pre>
				</div>
				<div>
					<p class="terminal-label">REFRESH LOG</p>
					<pre aria-live="polite">{refreshLog ||
							(streamState === 'loading'
								? 'Loading the latest refresh log…'
								: 'No refresh events recorded.')}</pre>
				</div></Card.Content
			></Card.Root
		>
	</div>
</main>
