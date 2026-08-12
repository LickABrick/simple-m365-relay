<script lang="ts">
	import { progressive } from '$lib/actions/progressive';
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
	import Arrow from '@lucide/svelte/icons/arrow-right';
	import Check from '@lucide/svelte/icons/check';
	let { data, form } = $props();
	// svelte-ignore state_referenced_locally
	const relay = superForm(data.relayForm, { validators: zod4Client(relaySettingsSchema) });
	// svelte-ignore state_referenced_locally
	const network = superForm(data.networkForm, { validators: zod4Client(networkSettingsSchema) });
	// svelte-ignore state_referenced_locally
	const microsoft = superForm(data.microsoftForm, {
		validators: zod4Client(microsoftSettingsSchema)
	});
	// svelte-ignore state_referenced_locally
	const client = superForm(data.clientForm, { validators: zod4Client(smtpClientSchema) });
	const { form: relayForm, enhance: relayEnhance } = relay;
	const { form: networkForm, enhance: networkEnhance } = network;
	const { form: microsoftForm, enhance: microsoftEnhance } = microsoft;
	const { form: clientForm, enhance: clientEnhance } = client;
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
						><FormTextField
							form={relay}
							name="hostname"
							label="Relay hostname"
							bind:value={$relayForm.hostname}
						/>
						<FormTextField
							form={relay}
							name="domain"
							label="Relay domain"
							bind:value={$relayForm.domain}
						/>
						<FormTextField
							form={relay}
							name="relayhost"
							label="Upstream relay"
							bind:value={$relayForm.relayhost}
						/>
						><Button type="submit">Save and continue<Arrow data-icon="inline-end" /></Button
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
								><Field.FieldLabel>Port 25 TLS</Field.FieldLabel><Select.Root
									name="tls_25"
									type="single"
									bind:value={$networkForm.tls_25}
									><Select.Trigger>{data.config.tls.smtpd_25}</Select.Trigger><Select.Content
										><Select.Group
											>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
													>{value}</Select.Item
												>{/each}</Select.Group
										></Select.Content
									></Select.Root
								></Field.Field
							><Field.Field
								><Field.FieldLabel>Port 587 TLS</Field.FieldLabel><Select.Root
									name="tls_587"
									type="single"
									bind:value={$networkForm.tls_587}
									><Select.Trigger>{data.config.tls.smtpd_587}</Select.Trigger><Select.Content
										><Select.Group
											>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
													>{value}</Select.Item
												>{/each}</Select.Group
										></Select.Content
									></Select.Root
								></Field.Field
							>
						</div>
						<Button type="submit">Save and continue<Arrow data-icon="inline-end" /></Button
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
							bind:value={$microsoftForm.ms365_smtp_user}
						/>
						<FormTextField
							form={microsoft}
							name="tenant_id"
							label="Tenant ID"
							bind:value={$microsoftForm.tenant_id}
						/>
						<FormTextField
							form={microsoft}
							name="client_id"
							label="Application client ID"
							bind:value={$microsoftForm.client_id}
						/>
						><input
							type="hidden"
							name="auto_refresh_minutes"
							bind:value={$microsoftForm.auto_refresh_minutes}
						/><Button type="submit">Save and continue<Arrow data-icon="inline-end" /></Button
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
				><form method="POST" action="?/start" use:progressive>
					<input type="hidden" name="csrf" value={data.csrf} /><Button type="submit"
						>Start authorization</Button
					>
				</form>
				<pre>{data.deviceLog || 'Waiting to start device authorization.'}</pre>
				<pre>{JSON.stringify(data.token, null, 2)}</pre>
				<Button href="/onboarding/client" disabled={!Object.keys(data.token).length}
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
						><FormTextField
							form={client}
							name="login"
							label="Login"
							bind:value={$clientForm.login}
						/>
						<FormTextField
							form={client}
							name="password"
							label="Password"
							type="password"
							bind:value={$clientForm.password}
						/>
						><Button type="submit">Save and review<Arrow data-icon="inline-end" /></Button
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
						<span>OAuth token</span><Badge
							variant={Object.keys(data.token).length ? 'secondary' : 'destructive'}
							>{Object.keys(data.token).length ? 'Detected' : 'Missing'}</Badge
						>
					</div>
					<div>
						<span>SMTP clients</span><Badge variant={data.users.length ? 'secondary' : 'outline'}
							>{data.users.length} configured</Badge
						>
					</div>
				</div></Card.Content
			><Card.Footer
				><form method="POST" action="?/finish" use:progressive>
					<input type="hidden" name="csrf" value={data.csrf} /><Button type="submit"
						>Validate, apply, and finish</Button
					>
				</form></Card.Footer
			></Card.Root
		>{/if}
	<footer class="onboarding-footer">
		{#if previous[data.step]}<Button href={`/onboarding/${previous[data.step]}`} variant="ghost"
				>← Back</Button
			>{/if}<Button href="/overview" variant="ghost">Exit setup</Button>
	</footer>
</main>
