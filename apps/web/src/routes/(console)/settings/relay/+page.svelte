<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { relaySettingsSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Badge } from '$lib/components/ui/badge';
	import { toast } from 'svelte-sonner';
	import ShieldCheck from '@lucide/svelte/icons/shield-check';
	import { progressive } from '$lib/actions/progressive';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	const settings = superForm(data.settingsForm, {
		validators: zod4Client(relaySettingsSchema),
		onResult: ({ result }) => {
			if (result.type === 'success')
				toast.success((result.data as { message?: string })?.message || 'Saved');
		}
	});
	const { form, enhance, submitting } = settings;
</script>

<main class="console-page narrow-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/settings/relay</p>
			<h1>Relay identity</h1>
			<p>
				Define this relay and its Microsoft 365 upstream. Saving is intentionally separate from
				applying.
			</p>
		</div>
		{#if data.pending}<Badge variant="secondary">UNAPPLIED</Badge>{/if}
	</header>
	<Card.Root
		><Card.Header
			><Card.Title>Postfix identity</Card.Title><Card.Description
				>Values are validated in the browser and again on the server.</Card.Description
			></Card.Header
		><Card.Content>
			<form method="POST" action="?/save" use:enhance>
				<Field.FieldGroup>
					<input type="hidden" name="csrf" bind:value={$form.csrf} />
					<FormTextField
						form={settings}
						name="hostname"
						label="Relay hostname"
						bind:value={$form.hostname}
						description="Fully-qualified name advertised to SMTP clients."
					/>
					<FormTextField
						form={settings}
						name="domain"
						label="Local relay domain"
						bind:value={$form.domain}
					/>
					<FormTextField
						form={settings}
						name="relayhost"
						label="Upstream relay"
						bind:value={$form.relayhost}
						description="Microsoft 365 normally uses [smtp.office365.com]:587."
					/>
					<Button type="submit" disabled={$submitting}
						>{$submitting ? 'Saving…' : 'Save relay settings'}</Button
					>
				</Field.FieldGroup>
			</form>
		</Card.Content></Card.Root
	>
	<Card.Root
		><Card.Header
			><Card.Title>Deployment gate</Card.Title><Card.Description
				>Validate renders an isolated Postfix configuration. Apply validates again, renders, and
				reloads.</Card.Description
			></Card.Header
		><Card.Footer class="action-row">
			<form method="POST" action="?/validate" use:progressive>
				<input type="hidden" name="csrf" value={$form.csrf} /><Button
					type="submit"
					variant="outline"><ShieldCheck data-icon="inline-start" />Validate</Button
				>
			</form>
			<form method="POST" action="?/apply" use:progressive>
				<input type="hidden" name="csrf" value={$form.csrf} /><Button
					type="submit"
					disabled={!data.pending}>Apply changes</Button
				>
			</form>
			<form method="POST" action="?/discard" use:progressive>
				<input type="hidden" name="csrf" value={$form.csrf} /><Button
					type="submit"
					variant="ghost"
					disabled={!data.pending}>Discard</Button
				>
			</form>
		</Card.Footer></Card.Root
	>
</main>
