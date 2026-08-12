<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { networkSettingsSchema } from '$lib/forms/schemas';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import * as Select from '$lib/components/ui/select';
	import { Textarea } from '$lib/components/ui/textarea';
	import { Spinner } from '$lib/components/ui/spinner';
	import { toast } from 'svelte-sonner';
	import { untrack } from 'svelte';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	const network = superForm(
		untrack(() => data.networkForm),
		{
			validators: zod4Client(networkSettingsSchema),
			applyAction: false,
			invalidateAll: false,
			onResult: ({ result }) => {
				if (result.type === 'success') {
					const saved = (result.data as { form?: { data?: (typeof data.networkForm)['data'] } })
						?.form?.data;
					if (saved) queueMicrotask(() => network.reset({ data: saved, newState: saved }));
					toast.success('Network policy saved.');
				} else if (result.type === 'failure')
					toast.error(
						(result.data as { error?: string })?.error || 'Network policy could not be saved.'
					);
			}
		}
	);
	const { form, errors, enhance, submitting, tainted } = network;
	const changed = $derived(network.isTainted($tainted));
</script>

<main class="console-page narrow-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/settings/network</p>
			<h1>Network & TLS</h1>
			<p>Control who may relay and the encryption floor offered on each listener.</p>
		</div>
	</header>
	<Card.Root
		><Card.Header
			><Card.Title>Trust boundary</Card.Title><Card.Description
				>Every network here can submit mail without SMTP authentication. Prefer the smallest
				possible ranges.</Card.Description
			></Card.Header
		><Card.Content>
			<form method="POST" use:enhance>
				<input type="hidden" name="csrf" bind:value={$form.csrf} /><Field.FieldGroup>
					<Field.Field data-invalid={Boolean($errors.mynetworks)}
						><Field.FieldLabel for="mynetworks">Trusted networks</Field.FieldLabel><Textarea
							id="mynetworks"
							name="mynetworks"
							rows={7}
							bind:value={$form.mynetworks}
							aria-invalid={Boolean($errors.mynetworks)}
						/><Field.FieldDescription>One IPv4 or IPv6 CIDR per line.</Field.FieldDescription
						>{#if $errors.mynetworks}<Field.FieldError>{$errors.mynetworks}</Field.FieldError
							>{/if}</Field.Field
					>
					<div class="form-grid">
						<Field.Field
							><Field.FieldLabel for="tls25">Port 25 TLS</Field.FieldLabel><Select.Root
								name="tls_25"
								type="single"
								bind:value={$form.tls_25}
								><Select.Trigger id="tls25">{$form.tls_25}</Select.Trigger><Select.Content
									><Select.Group
										>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
												>{value}</Select.Item
											>{/each}</Select.Group
									></Select.Content
								></Select.Root
							></Field.Field
						>
						<Field.Field
							><Field.FieldLabel for="tls587">Port 587 TLS</Field.FieldLabel><Select.Root
								name="tls_587"
								type="single"
								bind:value={$form.tls_587}
								><Select.Trigger id="tls587">{$form.tls_587}</Select.Trigger><Select.Content
									><Select.Group
										>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
												>{value}</Select.Item
											>{/each}</Select.Group
									></Select.Content
								></Select.Root
							></Field.Field
						>
					</div>
					<Button type="submit" disabled={$submitting || !changed}
						>{#if $submitting}<Spinner data-icon="inline-start" />{/if}{$submitting
							? 'Saving…'
							: 'Save network policy'}</Button
					>
				</Field.FieldGroup>
			</form></Card.Content
		></Card.Root
	>
</main>
