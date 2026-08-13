<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { untrack } from 'svelte';
	import { toast } from 'svelte-sonner';
	import { changePasswordSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Spinner } from '$lib/components/ui/spinner';
	import KeyRound from '@lucide/svelte/icons/key-round';

	let { data } = $props();
	const password = superForm(
		untrack(() => data.passwordForm),
		{
			validators: zod4Client(changePasswordSchema),
			applyAction: false,
			invalidateAll: false,
			resetForm: true,
			onResult: ({ result }) => {
				if (result.type === 'success') toast.success('Administrator password changed.');
				else if (result.type === 'failure')
					toast.error(
						(result.data as { error?: string })?.error || 'Password could not be changed.'
					);
			}
		}
	);
	const { form, enhance, submitting } = password;
</script>

<main class="console-page narrow-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/system/account</p>
			<h1>Administrator account</h1>
			<p>Change the password used to access this control plane.</p>
		</div>
	</header>
	<Card.Root>
		<Card.Header>
			<Card.Title>Change password</Card.Title>
			<Card.Description>Your active session remains signed in after the change.</Card.Description>
		</Card.Header>
		<Card.Content>
			<form method="POST" use:enhance>
				<input type="hidden" name="csrf" bind:value={$form.csrf} />
				<Field.FieldGroup>
					<FormTextField
						form={password}
						name="currentPassword"
						label="Current password"
						type="password"
						autocomplete="current-password"
					/>
					<FormTextField
						form={password}
						name="password"
						label="New password"
						type="password"
						autocomplete="new-password"
						description="At least 12 characters with upper, lower, number, and symbol."
					/>
					<FormTextField
						form={password}
						name="confirm"
						label="Confirm new password"
						type="password"
						autocomplete="new-password"
					/>
					<Button
						type="submit"
						disabled={$submitting || !$form.currentPassword || !$form.password || !$form.confirm}
					>
						{#if $submitting}<Spinner data-icon="inline-start" />{:else}<KeyRound
								data-icon="inline-start"
							/>{/if}
						{$submitting ? 'Changing password…' : 'Change password'}
					</Button>
				</Field.FieldGroup>
			</form>
		</Card.Content>
	</Card.Root>
</main>
