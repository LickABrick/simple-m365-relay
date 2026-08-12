<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { loginSchema } from '$lib/forms/schemas';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import LogIn from '@lucide/svelte/icons/log-in';
	import { Spinner } from '$lib/components/ui/spinner';
	import { untrack } from 'svelte';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	const login = superForm(
		untrack(() => data.loginForm),
		{ validators: zod4Client(loginSchema) }
	);
	const { form, enhance, submitting } = login;
</script>

<main class="auth-shell">
	<section class="auth-intro" aria-labelledby="login-title">
		<p class="eyebrow">Local administration</p>
		<h1 id="login-title">One relay. One control surface.</h1>
		<p>
			Manage Microsoft 365 OAuth, SMTP clients, sender identities, and delivery evidence without
			exposing the control API to the browser.
		</p>
	</section>
	<Card.Root class="auth-card"
		><Card.Header
			><Card.Title>Sign in</Card.Title><Card.Description
				>Use the administrator account stored on this relay.</Card.Description
			></Card.Header
		><Card.Content>
			<form method="POST" use:enhance>
				<Field.FieldGroup
					><FormTextField
						form={login}
						name="username"
						label="Username"
						autocomplete="username"
						autofocus
					/><FormTextField
						form={login}
						name="password"
						label="Password"
						type="password"
						autocomplete="current-password"
					/>
					<Button type="submit" disabled={$submitting || !$form.username || !$form.password}
						>{#if $submitting}<Spinner data-icon="inline-start" />{:else}<LogIn
								data-icon="inline-start"
							/>{/if}{$submitting ? 'Signing in…' : 'Sign in'}</Button
					></Field.FieldGroup
				>
			</form></Card.Content
		></Card.Root
	>
</main>
