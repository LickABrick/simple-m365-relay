<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { smtpClientSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { progressive } from '$lib/actions/progressive';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import * as Table from '$lib/components/ui/table';
	import Trash from '@lucide/svelte/icons/trash-2';
	import Users from '@lucide/svelte/icons/users';
	import { toast } from 'svelte-sonner';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	const client = superForm(data.clientForm, {
		validators: zod4Client(smtpClientSchema),
		onResult: ({ result }) => {
			if (result.type === 'success') toast.success('SMTP client saved.');
		}
	});
	const { form, enhance, submitting } = client;
</script>

<main class="console-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/access/clients</p>
			<h1>SMTP clients</h1>
			<p>Credentials used by applications and devices submitting mail to this relay.</p>
		</div>
	</header>
	<div class="two-panel">
		<Card.Root
			><Card.Header
				><Card.Title>Add or rotate credentials</Card.Title><Card.Description
					>Submitting an existing login replaces its password.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/add" use:enhance>
					<input type="hidden" name="csrf" bind:value={$form.csrf} /><Field.FieldGroup
						><FormTextField
							form={client}
							name="login"
							label="Login"
							bind:value={$form.login}
							autocomplete="username"
						/><FormTextField
							form={client}
							name="password"
							label="Password"
							type="password"
							bind:value={$form.password}
							autocomplete="new-password"
							description="At least 12 characters with upper, lower, number, and symbol."
						/><Button type="submit" disabled={$submitting}
							>{$submitting ? 'Saving…' : 'Save client'}</Button
						></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		>
		<Card.Root
			><Card.Header
				><Card.Title>Authorized clients</Card.Title><Card.Description
					>{data.users.length} configured</Card.Description
				></Card.Header
			><Card.Content
				>{#if data.users.length}<Table.Root
						><Table.Header
							><Table.Row
								><Table.Head>Login</Table.Head><Table.Head
									><span class="sr-only">Actions</span></Table.Head
								></Table.Row
							></Table.Header
						><Table.Body
							>{#each data.users as user}<Table.Row
									><Table.Cell class="font-mono">{user}</Table.Cell><Table.Cell
										><form method="POST" action="?/delete" use:progressive>
											<input type="hidden" name="csrf" value={$form.csrf} /><input
												type="hidden"
												name="login"
												value={user}
											/><Button
												type="submit"
												variant="ghost"
												size="icon"
												aria-label={`Delete ${user}`}><Trash /></Button
											>
										</form></Table.Cell
									></Table.Row
								>{/each}</Table.Body
						></Table.Root
					>{:else}<Empty.Root
						><Empty.Header
							><Empty.Media variant="icon"><Users /></Empty.Media><Empty.Title
								>No SMTP clients</Empty.Title
							><Empty.Description
								>Create a credential for the first submitting application.</Empty.Description
							></Empty.Header
						></Empty.Root
					>{/if}</Card.Content
			></Card.Root
		>
	</div>
</main>
