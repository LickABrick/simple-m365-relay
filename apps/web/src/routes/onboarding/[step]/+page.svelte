<script lang="ts">
	import ProgressiveForm from '$lib/components/progressive-form.svelte';
	import { onMount, untrack } from 'svelte';
	import { connectLiveStream, type LiveState } from '$lib/client/live-stream';
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import {
		microsoftSettingsSchema,
		networkSettingsSchema,
		relaySettingsSchema,
		smtpClientSchema
	} from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import * as Select from '$lib/components/ui/select';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Spinner } from '$lib/components/ui/spinner';
	import Arrow from '@lucide/svelte/icons/arrow-right';
	import Check from '@lucide/svelte/icons/check';
	let { data, form } = $props();
	// svelte-ignore state_referenced_locally
	const relay = superForm(
		untrack(() => data.relayForm),
		{
			validators: zod4Client(relaySettingsSchema)
		}
	);
	// svelte-ignore state_referenced_locally
	const network = superForm(
		untrack(() => data.networkForm),
		{
			validators: zod4Client(networkSettingsSchema)
		}
	);
	// svelte-ignore state_referenced_locally
	const microsoft = superForm(
		untrack(() => data.microsoftForm),
		{
			validators: zod4Client(microsoftSettingsSchema)
		}
	);
	// svelte-ignore state_referenced_locally
	const client = superForm(
		untrack(() => data.clientForm),
		{
			validators: zod4Client(smtpClientSchema)
		}
	);
	const { form: relayForm, enhance: relayEnhance, submitting: relaySubmitting } = relay;
	const { form: networkForm, enhance: networkEnhance, submitting: networkSubmitting } = network;
	const {
		form: microsoftForm,
		enhance: microsoftEnhance,
		submitting: microsoftSubmitting
	} = microsoft;
	const { form: clientForm, enhance: clientEnhance, submitting: clientSubmitting } = client;
	// svelte-ignore state_referenced_locally
	let token = $state(data.token),
		deviceLog = $state(data.deviceLog),
		streamState = $state<LiveState>('loading');
	onMount(() => {
		if (data.step !== 'authorize') return;
		return connectLiveStream<{
			token: Record<string, unknown>;
			deviceLog: string;
			refreshLog: string;
		}>({
			url: '/api/live?scope=microsoft',
			ondata: (next) => {
				token = next.token;
				deviceLog = next.deviceLog;
			},
			onstate: (state) => (streamState = state)
		});
	});
	const tokenPresent = $derived(token['ok'] === true);
	const readyToFinish = $derived(
		Boolean(
			data.health &&
			data.config.oauth.client_id &&
			data.config.oauth.tenant_id &&
			data.config.ms365_smtp_user &&
			tokenPresent &&
			data.users.length
		)
	);
	const labels: { [key: string]: string } = {
		relay: 'Relay identity',
		network: 'Trust boundary',
		microsoft: 'Microsoft 365',
		authorize: 'OAuth authorization',
		client: 'SMTP client',
		review: 'Readiness review'
	};
	const previous: { [key: string]: string } = {
		network: 'relay',
		microsoft: 'network',
		authorize: 'microsoft',
		client: 'authorize',
		review: 'client'
	};
</script>

<main class="onboarding-shell">
	<header class="onboarding-step-header">
		<div>
			<a href="/onboarding">← Setup index</a>
			<p class="command-path">INITIALIZATION / {data.step.toUpperCase()}</p>
			<h1>{labels[data.step]}</h1>
		</div>
		<Badge variant="outline"
			>STEP {['relay', 'network', 'microsoft', 'authorize', 'client', 'review'].indexOf(data.step) +
				1} / 6</Badge
		>
	</header>
	{#if form?.error}<p class="form-fault" role="alert">{form.error}</p>{/if}
	{#if data.step === 'relay'}<Card.Root
			><Card.Header
				><Card.Title>Identify this relay</Card.Title><Card.Description
					>These values are advertised by Postfix and used to qualify local mail.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/save" use:relayEnhance>
					<input type="hidden" name="csrf" bind:value={$relayForm.csrf} /><Field.FieldGroup
						><FormTextField form={relay} name="hostname" label="Relay hostname" />
						<FormTextField form={relay} name="domain" label="Relay domain" />
						<FormTextField form={relay} name="relayhost" label="Upstream relay" />
						><Button type="submit" disabled={$relaySubmitting}
							>{#if $relaySubmitting}<Spinner data-icon="inline-start" />{/if}{$relaySubmitting
								? 'Saving…'
								: 'Save and continue'}{#if !$relaySubmitting}<Arrow
									data-icon="inline-end"
								/>{/if}</Button
						></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		>
	{:else if data.step === 'network'}<Card.Root
			><Card.Header
				><Card.Title>Set the trust boundary</Card.Title><Card.Description
					>Only add networks whose hosts may submit mail without SMTP authentication.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/save" use:networkEnhance>
					<input type="hidden" name="csrf" bind:value={$networkForm.csrf} /><Field.FieldGroup
						><Field.Field
							><Field.FieldLabel for="mynetworks">Trusted networks</Field.FieldLabel><Textarea
								id="mynetworks"
								name="mynetworks"
								rows={6}
								bind:value={$networkForm.mynetworks}
								required
							/></Field.Field
						>
						<div class="form-grid">
							<Field.Field
								><Field.FieldLabel for="onboarding-tls25">Port 25 TLS</Field.FieldLabel><Select.Root
									name="tls_25"
									type="single"
									bind:value={$networkForm.tls_25}
									><Select.Trigger id="onboarding-tls25">{$networkForm.tls_25}</Select.Trigger
									><Select.Content
										><Select.Group
											>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
													>{value}</Select.Item
												>{/each}</Select.Group
										></Select.Content
									></Select.Root
								></Field.Field
							><Field.Field
								><Field.FieldLabel for="onboarding-tls587">Port 587 TLS</Field.FieldLabel
								><Select.Root name="tls_587" type="single" bind:value={$networkForm.tls_587}
									><Select.Trigger id="onboarding-tls587">{$networkForm.tls_587}</Select.Trigger
									><Select.Content
										><Select.Group
											>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
													>{value}</Select.Item
												>{/each}</Select.Group
										></Select.Content
									></Select.Root
								></Field.Field
							>
						</div>
						<Button type="submit" disabled={$networkSubmitting}
							>{#if $networkSubmitting}<Spinner data-icon="inline-start" />{/if}{$networkSubmitting
								? 'Saving…'
								: 'Save and continue'}{#if !$networkSubmitting}<Arrow
									data-icon="inline-end"
								/>{/if}</Button
						></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		>
	{:else if data.step === 'microsoft'}<Card.Root
			><Card.Header
				><Card.Title>Connect Microsoft 365</Card.Title><Card.Description
					>Use a licensed mailbox and a public-client Entra application with device flow enabled.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/save" use:microsoftEnhance>
					<input type="hidden" name="csrf" bind:value={$microsoftForm.csrf} /><Field.FieldGroup
						><FormTextField
							form={microsoft}
							name="ms365_smtp_user"
							label="Sending mailbox"
							type="email"
						/>
						<FormTextField form={microsoft} name="tenant_id" label="Tenant ID" />
						<FormTextField form={microsoft} name="client_id" label="Application client ID" />
						><input
							type="hidden"
							name="auto_refresh_minutes"
							bind:value={$microsoftForm.auto_refresh_minutes}
						/><Button type="submit" disabled={$microsoftSubmitting}
							>{#if $microsoftSubmitting}<Spinner
									data-icon="inline-start"
								/>{/if}{$microsoftSubmitting
								? 'Saving…'
								: 'Save and continue'}{#if !$microsoftSubmitting}<Arrow
									data-icon="inline-end"
								/>{/if}</Button
						></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		>
	{:else if data.step === 'authorize'}<Card.Root
			><Card.Header
				><Card.Title>Authorize the sending mailbox</Card.Title><Card.Description
					>Start the device flow, follow the Microsoft URL/code in the live log, then continue when
					token status is present.</Card.Description
				></Card.Header
			><Card.Content class="stack"
				><ProgressiveForm method="POST" action="?/start">
					{#snippet children(pending)}<input type="hidden" name="csrf" value={data.csrf} /><Button
							type="submit"
							disabled={pending || !data.health}
							>{#if pending}<Spinner data-icon="inline-start" />{/if}{pending
								? 'Starting…'
								: 'Start authorization'}</Button
						>{/snippet}
				</ProgressiveForm>
				<Badge variant={streamState === 'live' ? 'secondary' : 'outline'}
					>{streamState === 'live'
						? 'LIVE'
						: streamState === 'paused'
							? 'PAUSED'
							: streamState === 'loading'
								? 'CONNECTING'
								: 'RETRYING'}</Badge
				>
				<pre aria-live="polite">{deviceLog || 'Waiting to start device authorization.'}</pre>
				<pre aria-live="polite">{JSON.stringify(token, null, 2)}</pre>
				<Button href="/onboarding/client" disabled={!tokenPresent}
					>Continue<Arrow data-icon="inline-end" /></Button
				></Card.Content
			></Card.Root
		>
	{:else if data.step === 'client'}<Card.Root
			><Card.Header
				><Card.Title>Create the first SMTP client</Card.Title><Card.Description
					>This credential belongs to a device or application, not a human administrator.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/client" use:clientEnhance>
					<input type="hidden" name="csrf" bind:value={$clientForm.csrf} /><Field.FieldGroup
						><FormTextField form={client} name="login" label="Login" />
						<FormTextField form={client} name="password" label="Password" type="password" />
						><Button type="submit" disabled={$clientSubmitting || !data.health}
							>{#if $clientSubmitting}<Spinner data-icon="inline-start" />{/if}{$clientSubmitting
								? 'Saving…'
								: 'Save and review'}{#if !$clientSubmitting}<Arrow
									data-icon="inline-end"
								/>{/if}</Button
						></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		>
	{:else}<Card.Root
			><Card.Header
				><Card.Title>Readiness gate</Card.Title><Card.Description
					>Finishing validates the generated Postfix configuration and reloads the relay.</Card.Description
				></Card.Header
			><Card.Content
				><div class="readiness-list">
					<div><span>Relay identity</span><Badge><Check />Configured</Badge></div>
					<div>
						<span>Trusted networks</span><Badge
							><Check />{data.config.mynetworks.length} ranges</Badge
						>
					</div>
					<div>
						<span>Microsoft application</span><Badge
							variant={data.config.oauth.client_id ? 'secondary' : 'destructive'}
							>{data.config.oauth.client_id ? 'Configured' : 'Missing'}</Badge
						>
					</div>
					<div>
						<span>OAuth token</span><Badge variant={tokenPresent ? 'secondary' : 'destructive'}
							>{tokenPresent ? 'Detected' : 'Missing'}</Badge
						>
					</div>
					<div>
						<span>SMTP clients</span><Badge variant={data.users.length ? 'secondary' : 'outline'}
							>{data.users.length} configured</Badge
						>
					</div>
				</div></Card.Content
			><Card.Footer
				><ProgressiveForm method="POST" action="?/finish">
					{#snippet children(pending)}<input type="hidden" name="csrf" value={data.csrf} /><Button
							type="submit"
							disabled={pending || !readyToFinish}
							>{#if pending}<Spinner data-icon="inline-start" />{/if}{pending
								? 'Applying…'
								: 'Validate, apply, and finish'}</Button
						>{/snippet}
				</ProgressiveForm></Card.Footer
			></Card.Root
		>{/if}
	<footer class="onboarding-footer">
		{#if previous[data.step]}<Button href={`/onboarding/${previous[data.step]}`} variant="ghost"
				>← Back</Button
			>{/if}<Button href="/overview" variant="ghost">Exit setup</Button>
	</footer>
</main>
