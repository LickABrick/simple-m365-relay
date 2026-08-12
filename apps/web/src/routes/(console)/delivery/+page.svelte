<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { testMailSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Spinner } from '$lib/components/ui/spinner';
	import Send from '@lucide/svelte/icons/send';
	import { toast } from 'svelte-sonner';
	import { relayState } from '$lib/client/relay-state.svelte';
	import { untrack } from 'svelte';
	let { data, form: result } = $props();
	// svelte-ignore state_referenced_locally
	const test = superForm(
		untrack(() => data.testForm),
		{
			validators: zod4Client(testMailSchema),
			applyAction: false,
			invalidateAll: false,
			onResult: ({ result }) => {
				if (result.type === 'success') toast.success('Test message accepted.');
				else if (result.type === 'failure')
					toast.error((result.data as { error?: string })?.error || 'Test message failed.');
			}
		}
	);
	const { form, enhance, submitting } = test;
</script>

<main class="console-page narrow-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/operations/delivery</p>
			<h1>Delivery probe</h1>
			<p>Submit through the relay and inspect the returned queue/delivery evidence.</p>
		</div>
	</header>
	<Card.Root
		><Card.Header
			><Card.Title>Test message</Card.Title><Card.Description
				>This uses the same local submission path as connected clients.</Card.Description
			></Card.Header
		><Card.Content
			><form method="POST" use:enhance>
				<input type="hidden" name="csrf" bind:value={$form.csrf} /><Field.FieldGroup
					><div class="form-grid">
						<FormTextField
							form={test}
							name="from_addr"
							label="From"
							type="email"
							required={false}
						/><FormTextField form={test} name="to_addr" label="To" type="email" />
					</div>
					<FormTextField form={test} name="subject" label="Subject" /><Field.Field
						><Field.FieldLabel for="body">Message</Field.FieldLabel><Textarea
							id="body"
							name="body"
							rows={7}
							bind:value={$form.body}
						/></Field.Field
					><Button type="submit" disabled={$submitting || !relayState.available || !$form.to_addr}
						>{#if $submitting}<Spinner data-icon="inline-start" />{:else}<Send
								data-icon="inline-start"
							/>{/if}{$submitting ? 'Submitting…' : 'Send test message'}</Button
					></Field.FieldGroup
				>
			</form>
			{#if !relayState.available}<p class="telemetry-note">
					Delivery tests are unavailable while the relay is offline.
				</p>{/if}</Card.Content
		></Card.Root
	>{#if result?.delivery}<Card.Root
			><Card.Header><Card.Title>Delivery evidence</Card.Title></Card.Header><Card.Content
				><pre>{JSON.stringify(result.delivery, null, 2)}</pre></Card.Content
			></Card.Root
		>{/if}
</main>
