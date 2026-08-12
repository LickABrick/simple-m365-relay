<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { setupSchema } from '$lib/forms/schemas';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import ShieldCheck from '@lucide/svelte/icons/shield-check';
	import { Spinner } from '$lib/components/ui/spinner';
	import { untrack } from 'svelte';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	const setup = superForm(
		untrack(() => data.setupForm),
		{
			validators: zod4Client(setupSchema)
		}
	);
	const { form, enhance, submitting } = setup;
</script>

<main class="auth-shell">
	<section class="auth-intro" aria-labelledby="setup-title">
		<p class="eyebrow">Simple M365 Relay · v2</p>
		<h1 id="setup-title">Secure the control plane before mail starts moving.</h1>
		<p>
			Create the single local administrator. Credentials stay on this host and are hashed with
			Argon2.
		</p>
	</section>
	<Card.Root class="auth-card"
		><Card.Header
			><Card.Title>Administrator setup</Card.Title><Card.Description
				>This account controls relay identities, trusted networks, and OAuth.</Card.Description
			></Card.Header
		><Card.Content>
			<form method="POST" use:enhance>
				<Field.FieldGroup
					><FormTextField
						form={setup}
						name="username"
						label="Username"
						autocomplete="username"
					/><FormTextField
						form={setup}
						name="password"
						label="Password"
						type="password"
						autocomplete="new-password"
						description="At least 12 characters with upper, lower, number, and symbol."
					/><FormTextField
						form={setup}
						name="confirm"
						label="Confirm password"
						type="password"
						autocomplete="new-password"
					/>
					<Button
						type="submit"
						disabled={$submitting || !$form.username || !$form.password || !$form.confirm}
						>{#if $submitting}<Spinner data-icon="inline-start" />{:else}<ShieldCheck
								data-icon="inline-start"
							/>{/if}{$submitting ? 'Creating…' : 'Create administrator'}</Button
					></Field.FieldGroup
				>
			</form>
		</Card.Content></Card.Root
	>
</main>
