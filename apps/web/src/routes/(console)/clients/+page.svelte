<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { smtpClientSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import ProgressiveForm from '$lib/components/progressive-form.svelte';
	import * as AlertDialog from '$lib/components/ui/alert-dialog';
	import { Button, buttonVariants } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import { Spinner } from '$lib/components/ui/spinner';
	import * as Table from '$lib/components/ui/table';
	import Trash from '@lucide/svelte/icons/trash-2';
	import Users from '@lucide/svelte/icons/users';
	import { toast } from 'svelte-sonner';
	import { relayState } from '$lib/client/relay-state.svelte';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let users = $state(data.users);
	// svelte-ignore state_referenced_locally
	const client = superForm(data.clientForm, {
		validators: zod4Client(smtpClientSchema),
		invalidateAll: false,
		resetForm: true,
		onResult: ({ result }) => {
			if (result.type === 'success') {
				users = (result.data as { users?: string[] })?.users || users;
				toast.success('SMTP client saved.');
			} else if (result.type === 'failure')
				toast.error(
					(result.data as { error?: string })?.error || 'SMTP client could not be saved.'
				);
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
		<Card.Root>
			<Card.Header>
				<Card.Title>Add or rotate credentials</Card.Title>
				<Card.Description>Submitting an existing login replaces its password.</Card.Description>
			</Card.Header>
			<Card.Content>
				<form method="POST" action="?/add" use:enhance>
					<input type="hidden" name="csrf" bind:value={$form.csrf} />
					<Field.FieldGroup>
						<FormTextField
							form={client}
							name="login"
							label="Login"
							bind:value={$form.login}
							autocomplete="username"
						/>
						<FormTextField
							form={client}
							name="password"
							label="Password"
							type="password"
							bind:value={$form.password}
							autocomplete="new-password"
							description="At least 12 characters with upper, lower, number, and symbol."
						/>
						<Button type="submit" disabled={$submitting || !relayState.available}>
							{#if $submitting}<Spinner data-icon="inline-start" />{/if}
							{$submitting ? 'Saving…' : 'Save client'}
						</Button>
						{#if !relayState.available}<Field.FieldDescription
								>The relay must be online to manage SMTP credentials.</Field.FieldDescription
							>{/if}
					</Field.FieldGroup>
				</form>
			</Card.Content>
		</Card.Root>
		<Card.Root>
			<Card.Header
				><Card.Title>Authorized clients</Card.Title><Card.Description
					>{users.length} configured</Card.Description
				></Card.Header
			>
			<Card.Content>
				{#if users.length}
					<Table.Root>
						<Table.Header
							><Table.Row
								><Table.Head>Login</Table.Head><Table.Head
									><span class="sr-only">Actions</span></Table.Head
								></Table.Row
							></Table.Header
						>
						<Table.Body>
							{#each users as user (user)}
								<Table.Row>
									<Table.Cell class="font-mono">{user}</Table.Cell>
									<Table.Cell>
										<AlertDialog.Root>
											<AlertDialog.Trigger
												class={buttonVariants({ variant: 'ghost', size: 'icon' })}
												aria-label={`Delete ${user}`}
												disabled={!relayState.available}><Trash /></AlertDialog.Trigger
											>
											<AlertDialog.Content>
												<AlertDialog.Header
													><AlertDialog.Title>Delete SMTP client?</AlertDialog.Title
													><AlertDialog.Description
														><span class="font-mono">{user}</span> will immediately lose relay access.
														This cannot be undone.</AlertDialog.Description
													></AlertDialog.Header
												>
												<AlertDialog.Footer>
													<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
													<ProgressiveForm
														method="POST"
														action="?/delete"
														onsucceeded={(payload) => (users = payload.users as string[])}
													>
														{#snippet children(pending)}<input
																type="hidden"
																name="csrf"
																value={$form.csrf}
															/><input type="hidden" name="login" value={user} /><AlertDialog.Action
																type="submit"
																variant="destructive"
																disabled={pending}
																>{#if pending}<Spinner data-icon="inline-start" />{/if}{pending
																	? 'Deleting…'
																	: 'Delete client'}</AlertDialog.Action
															>{/snippet}
													</ProgressiveForm>
												</AlertDialog.Footer>
											</AlertDialog.Content>
										</AlertDialog.Root>
									</Table.Cell>
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				{:else}
					<Empty.Root
						><Empty.Header
							><Empty.Media variant="icon"><Users /></Empty.Media><Empty.Title
								>No SMTP clients</Empty.Title
							><Empty.Description
								>Create a credential for the first submitting application.</Empty.Description
							></Empty.Header
						></Empty.Root
					>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
</main>
