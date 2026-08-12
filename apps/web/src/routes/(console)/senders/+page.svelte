<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { senderSchema } from '$lib/forms/schemas';
	import ProgressiveForm from '$lib/components/progressive-form.svelte';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import * as Select from '$lib/components/ui/select';
	import * as Table from '$lib/components/ui/table';
	import * as Alert from '$lib/components/ui/alert';
	import { Spinner } from '$lib/components/ui/spinner';
	import Trash from '@lucide/svelte/icons/trash-2';
	import { toast } from 'svelte-sonner';
	import { untrack } from 'svelte';
	import { analyzeOAuthCapabilities } from '$lib/oauth-capabilities';
	import CircleAlert from '@lucide/svelte/icons/circle-alert';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let config = $state(data.config);
	const sender = superForm(
		untrack(() => data.senderForm),
		{
			validators: zod4Client(senderSchema),
			applyAction: false,
			invalidateAll: false,
			resetForm: true,
			onResult: ({ result }) => {
				if (result.type === 'success') {
					config = (result.data as { config?: typeof data.config })?.config || config;
					toast.success('Sender identity allowed.');
				} else if (result.type === 'failure')
					toast.error(
						(result.data as { error?: string })?.error || 'Sender identity could not be saved.'
					);
			}
		}
	);
	const { form, enhance, submitting } = sender;
	const capabilities = $derived(analyzeOAuthCapabilities(config, data.token));
	const senderCapability = (login: string, address: string) =>
		capabilities.senders.find((sender) => sender.login === login && sender.address === address);
</script>

<main class="console-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/access/senders</p>
			<h1>Sender policy</h1>
			<p>Bind authenticated clients to the envelope-from identities they own.</p>
		</div>
	</header>
	{#if capabilities.identityMismatch}<Alert.Root
			><CircleAlert /><Alert.Title>Delegated mailbox access</Alert.Title><Alert.Description
				>The OAuth token belongs to {data.token.identity}, while outbound SMTP authenticates as {config.ms365_smtp_user}.
				Ensure the token user has the required Exchange mailbox and Send As rights, then confirm
				with a delivery test.</Alert.Description
			></Alert.Root
		>{:else if capabilities.requiresSendAs.length}<Alert.Root
			><CircleAlert /><Alert.Title
				>{capabilities.requiresSendAs.length} sender {capabilities.requiresSendAs.length === 1
					? 'identity requires'
					: 'identities require'} Exchange permission</Alert.Title
			><Alert.Description
				>Any address other than {config.ms365_smtp_user} needs Send As permission for that mailbox. Token
				scopes cannot prove mailbox-level Send As assignments; confirm them with a delivery test.</Alert.Description
			></Alert.Root
		>{/if}
	<div class="two-panel">
		<Card.Root
			><Card.Header
				><Card.Title>Allow identity</Card.Title><Card.Description
					>Local policy controls which client may submit an address. Exchange separately decides
					whether the Microsoft mailbox may send as it.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/add" use:enhance>
					<input type="hidden" name="csrf" bind:value={$form.csrf} /><Field.FieldGroup
						><Field.Field
							><Field.FieldLabel for="login">SMTP client</Field.FieldLabel><Select.Root
								name="login"
								type="single"
								bind:value={$form.login}
								><Select.Trigger id="login">{$form.login || 'Select a client'}</Select.Trigger
								><Select.Content
									><Select.Group
										>{#each data.users as user}<Select.Item value={user}>{user}</Select.Item
											>{/each}</Select.Group
									></Select.Content
								></Select.Root
							></Field.Field
						><FormTextField form={sender} name="address" label="From address" type="email" /><Button
							type="submit"
							disabled={$submitting || !data.users.length || !$form.login || !$form.address}
							>{#if $submitting}<Spinner data-icon="inline-start" />{/if}{$submitting
								? 'Saving…'
								: 'Allow sender'}</Button
						></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		><Card.Root
			><Card.Header
				><Card.Title>Effective map</Card.Title><Card.Description
					>Defaults are used when a client omits its From identity.</Card.Description
				></Card.Header
			><Card.Content
				><Table.Root
					><Table.Header
						><Table.Row
							><Table.Head>Client</Table.Head><Table.Head>Identity</Table.Head><Table.Head
								>Microsoft 365</Table.Head
							><Table.Head>Default</Table.Head><Table.Head></Table.Head></Table.Row
						></Table.Header
					><Table.Body
						>{#each Object.entries(config.allowed_from) as [login, addresses]}{#each addresses as address}<Table.Row
									><Table.Cell>{login}</Table.Cell><Table.Cell class="font-mono"
										>{address}</Table.Cell
									><Table.Cell
										><Badge
											variant={senderCapability(login, address)?.status === 'mailbox'
												? 'secondary'
												: 'outline'}
											>{senderCapability(login, address)?.status === 'mailbox'
												? 'MAILBOX'
												: 'VERIFY SEND AS'}</Badge
										></Table.Cell
									><Table.Cell
										>{#if config.default_from[login] === address}<Badge>DEFAULT</Badge
											>{:else}<ProgressiveForm
												method="POST"
												action="?/setDefault"
												onsucceeded={(payload) => (config = payload.config as typeof data.config)}
											>
												{#snippet children(pending)}
													<input type="hidden" name="csrf" value={$form.csrf} /><input
														type="hidden"
														name="login"
														value={login}
													/><input type="hidden" name="address" value={address} /><Button
														type="submit"
														disabled={pending}
														variant="ghost"
														size="sm"
														>{#if pending}<Spinner data-icon="inline-start" />{/if}{pending
															? 'Updating…'
															: 'Set default'}</Button
													>
												{/snippet}
											</ProgressiveForm>{/if}</Table.Cell
									><Table.Cell
										><ProgressiveForm
											method="POST"
											action="?/remove"
											onsucceeded={(payload) => (config = payload.config as typeof data.config)}
										>
											{#snippet children(pending)}
												<input type="hidden" name="csrf" value={$form.csrf} /><input
													type="hidden"
													name="login"
													value={login}
												/><input type="hidden" name="address" value={address} /><Button
													type="submit"
													disabled={pending}
													variant="ghost"
													size="icon"
													aria-label={`Remove ${address}`}
													>{#if pending}<Spinner />{:else}<Trash />{/if}</Button
												>
											{/snippet}
										</ProgressiveForm></Table.Cell
									></Table.Row
								>{/each}{/each}</Table.Body
					></Table.Root
				></Card.Content
			></Card.Root
		>
	</div>
</main>
