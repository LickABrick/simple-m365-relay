<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { testMailSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Textarea } from '$lib/components/ui/textarea';
	import Send from '@lucide/svelte/icons/send';
	import { toast } from 'svelte-sonner';
	let { data, form: result } = $props();
	// svelte-ignore state_referenced_locally
	const test = superForm(data.testForm, {
		validators: zod4Client(testMailSchema),
		onResult: ({ result }) => {
			if (result.type === 'success') toast.success('Test message accepted.');
		}
	});
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
							bind:value={$form.from_addr}
						/><FormTextField
							form={test}
							name="to_addr"
							label="To"
							type="email"
							bind:value={$form.to_addr}
						/>
					</div>
					<FormTextField
						form={test}
						name="subject"
						label="Subject"
						bind:value={$form.subject}
					/><Field.Field
						><Field.FieldLabel for="body">Message</Field.FieldLabel><Textarea
							id="body"
							name="body"
							rows={7}
							bind:value={$form.body}
						/></Field.Field
					><Button type="submit" disabled={$submitting}
						><Send data-icon="inline-start" />{$submitting
							? 'Submitting…'
							: 'Send test message'}</Button
					></Field.FieldGroup
				>
			</form></Card.Content
		></Card.Root
	>{#if result?.delivery}<Card.Root
			><Card.Header><Card.Title>Delivery evidence</Card.Title></Card.Header><Card.Content
				><pre>{JSON.stringify(result.delivery, null, 2)}</pre></Card.Content
			></Card.Root
		>{/if}
</main>
