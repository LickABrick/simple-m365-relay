<script lang="ts">
	import { enhance as kitEnhance } from '$app/forms';
	import type { Action } from 'svelte/action';
	import { toast } from 'svelte-sonner';
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { configSchema } from '$lib/forms/schemas';
	import AppShell from '$lib/components/app-shell.svelte';
	import * as Alert from '$lib/components/ui/alert';
	import { Badge } from '$lib/components/ui/badge';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Empty from '$lib/components/ui/empty';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import * as Select from '$lib/components/ui/select';
	import * as Table from '$lib/components/ui/table';
	import { Textarea } from '$lib/components/ui/textarea';
	import CheckCircle2 from '@lucide/svelte/icons/circle-check-big';
	import CircleAlert from '@lucide/svelte/icons/circle-alert';
	import Inbox from '@lucide/svelte/icons/inbox';
	import Trash2 from '@lucide/svelte/icons/trash-2';
	import Download from '@lucide/svelte/icons/download';
	let { data, form } = $props();
	// svelte-ignore state_referenced_locally
	const configuration = superForm(data.configForm, {
		validators: zod4Client(configSchema),
		onResult: ({ result }) => {
			if (result.type === 'success') toast.success('Configuration saved. Apply it when ready.');
		}
	});
	const { form: configData, errors: configErrors, enhance: configEnhance } = configuration;
	const enhanced: Action<HTMLFormElement> = (node) =>
		kitEnhance(node, () => async ({ result, update }) => {
			await update();
			if (result.type === 'success') {
				const payload = result.data as { message?: string };
				if (payload?.message) toast.success(payload.message);
			} else if (result.type === 'failure') {
				const payload = result.data as { error?: string };
				toast.error(payload?.error || 'The action failed.');
			}
		});
	const queueCount = $derived(
		data.queue.includes('Mail queue is empty')
			? 0
			: (data.queue.match(/^[A-F0-9]{5,}/gm) || []).length
	);
</script>

<AppShell csrf={data.csrf} user={data.user} version={data.version}
	>{#snippet children()}
		<main class="workspace">
			<header class="page-header">
				<div>
					<p class="eyebrow">Relay operations</p>
					<h1>Mail flow at a glance</h1>
					<p>
						Server-rendered status and configuration. Privileged requests stay inside the Docker
						network.
					</p>
				</div>
				{#if data.pending}<Badge variant="secondary">Changes pending</Badge>{:else}<Badge
						variant="outline">Configuration applied</Badge
					>{/if}
			</header>
			{#if form?.error}<Alert.Root variant="destructive"
					><CircleAlert /><Alert.Title>Action failed</Alert.Title><Alert.Description
						>{form.error}</Alert.Description
					></Alert.Root
				>{/if}
			<section id="overview" class="metric-grid" aria-label="Relay status">
				<Card.Root
					><Card.Header
						><Card.Description>Control service</Card.Description><Card.Title
							>{data.health ? 'Online' : 'Unavailable'}</Card.Title
						></Card.Header
					><Card.Content
						>{#if data.health}<Badge><CheckCircle2 />Healthy</Badge>{:else}<Badge
								variant="destructive">Check container</Badge
							>{/if}</Card.Content
					></Card.Root
				><Card.Root
					><Card.Header
						><Card.Description>Queued messages</Card.Description><Card.Title
							>{queueCount}</Card.Title
						></Card.Header
					><Card.Content><p class="muted">Current Postfix queue estimate</p></Card.Content
					></Card.Root
				><Card.Root
					><Card.Header
						><Card.Description>OAuth token</Card.Description><Card.Title
							>{Object.keys(data.token).length ? 'Detected' : 'Not ready'}</Card.Title
						></Card.Header
					><Card.Content><p class="muted">Microsoft 365 outbound identity</p></Card.Content
					></Card.Root
				>
			</section>

			<section id="configuration" class="section-block">
				<div class="section-heading">
					<div>
						<p class="eyebrow">01 · Configuration</p>
						<h2>Relay boundary</h2>
					</div>
					<p>Define who may submit mail and how it leaves this host.</p>
				</div>
				<Card.Root
					><Card.Header
						><Card.Title>Postfix and Microsoft 365</Card.Title><Card.Description
							>Saving does not alter the running service until Apply is selected.</Card.Description
						></Card.Header
					><Card.Content
						><form method="POST" use:configEnhance action="?/save">
							<input type="hidden" name="csrf" bind:value={$configData.csrf} /><Field.FieldGroup
								><div class="form-grid">
									<Field.Field
										><Field.FieldLabel for="hostname">Relay hostname</Field.FieldLabel><Input
											id="hostname"
											name="hostname"
											bind:value={$configData.hostname}
											aria-invalid={$configErrors.hostname ? 'true' : undefined}
											required
										/>{#if $configErrors.hostname}<Field.FieldError
												>{$configErrors.hostname}</Field.FieldError
											>{/if}</Field.Field
									><Field.Field
										><Field.FieldLabel for="domain">Relay domain</Field.FieldLabel><Input
											id="domain"
											name="domain"
											bind:value={$configData.domain}
											aria-invalid={$configErrors.domain ? 'true' : undefined}
											required
										/>{#if $configErrors.domain}<Field.FieldError
												>{$configErrors.domain}</Field.FieldError
											>{/if}</Field.Field
									>
								</div>
								<Field.Field
									><Field.FieldLabel for="mynetworks">Trusted networks</Field.FieldLabel><Textarea
										id="mynetworks"
										name="mynetworks"
										rows={3}
										bind:value={$configData.mynetworks}
									/><Field.FieldDescription
										>One CIDR per line. Keep this list as narrow as possible.</Field.FieldDescription
									></Field.Field
								>
								<div class="form-grid">
									<Field.Field
										><Field.FieldLabel for="relayhost">Upstream relay</Field.FieldLabel><Input
											id="relayhost"
											name="relayhost"
											bind:value={$configData.relayhost}
										/></Field.Field
									><Field.Field
										><Field.FieldLabel for="ms365_smtp_user">Microsoft 365 sender</Field.FieldLabel
										><Input
											id="ms365_smtp_user"
											name="ms365_smtp_user"
											type="email"
											bind:value={$configData.ms365_smtp_user}
										/></Field.Field
									>
								</div>
								<div class="form-grid">
									<Field.Field
										><Field.FieldLabel for="tls_25">Port 25 TLS</Field.FieldLabel><Select.Root
											name="tls_25"
											type="single"
											value={data.config.tls.smtpd_25}
											><Select.Trigger id="tls_25">{data.config.tls.smtpd_25}</Select.Trigger
											><Select.Content
												><Select.Group
													>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
															>{value}</Select.Item
														>{/each}</Select.Group
												></Select.Content
											></Select.Root
										></Field.Field
									><Field.Field
										><Field.FieldLabel for="tls_587">Port 587 TLS</Field.FieldLabel><Select.Root
											name="tls_587"
											type="single"
											value={data.config.tls.smtpd_587}
											><Select.Trigger id="tls_587">{data.config.tls.smtpd_587}</Select.Trigger
											><Select.Content
												><Select.Group
													>{#each ['none', 'may', 'encrypt'] as value}<Select.Item {value}
															>{value}</Select.Item
														>{/each}</Select.Group
												></Select.Content
											></Select.Root
										></Field.Field
									>
								</div>
								<div class="form-grid">
									<Field.Field
										><Field.FieldLabel for="tenant_id">Tenant ID</Field.FieldLabel><Input
											id="tenant_id"
											name="tenant_id"
											bind:value={$configData.tenant_id}
										/></Field.Field
									><Field.Field
										><Field.FieldLabel for="client_id">Application client ID</Field.FieldLabel
										><Input
											id="client_id"
											name="client_id"
											bind:value={$configData.client_id}
										/></Field.Field
									>
								</div>
								<Field.Field
									><Field.FieldLabel for="auto_refresh_minutes"
										>Token refresh interval</Field.FieldLabel
									><Input
										id="auto_refresh_minutes"
										name="auto_refresh_minutes"
										type="number"
										min="0"
										max="1440"
										bind:value={$configData.auto_refresh_minutes}
									/></Field.Field
								><Button type="submit">Save configuration</Button></Field.FieldGroup
							>
						</form></Card.Content
					><Card.Footer class="action-row"
						><form method="POST" use:enhanced action="?/apply">
							<input type="hidden" name="csrf" value={data.csrf} /><Button
								type="submit"
								disabled={!data.pending}>Validate and apply</Button
							>
						</form>
						<form method="POST" use:enhanced action="?/discard">
							<input type="hidden" name="csrf" value={data.csrf} /><Button
								type="submit"
								variant="outline"
								disabled={!data.pending}>Discard saved changes</Button
							>
						</form></Card.Footer
					></Card.Root
				>
			</section>

			<section id="clients" class="section-block">
				<div class="section-heading">
					<div>
						<p class="eyebrow">02 · Access</p>
						<h2>SMTP clients</h2>
					</div>
					<p>Credentials used by devices and applications submitting to this relay.</p>
				</div>
				<div class="split-grid">
					<Card.Root
						><Card.Header
							><Card.Title>Add or rotate a client</Card.Title><Card.Description
								>Saving an existing login replaces its password.</Card.Description
							></Card.Header
						><Card.Content
							><form method="POST" use:enhanced action="?/addUser">
								<input type="hidden" name="csrf" value={data.csrf} /><Field.FieldGroup
									><Field.Field
										><Field.FieldLabel for="login">Login</Field.FieldLabel><Input
											id="login"
											name="login"
											required
										/></Field.Field
									><Field.Field
										><Field.FieldLabel for="client-password">Password</Field.FieldLabel><Input
											id="client-password"
											name="password"
											type="password"
											minlength={12}
											required
										/></Field.Field
									><Button type="submit">Save SMTP client</Button></Field.FieldGroup
								>
							</form></Card.Content
						></Card.Root
					><Card.Root
						><Card.Header
							><Card.Title>Configured clients</Card.Title><Card.Description
								>{data.users.length} active login{data.users.length === 1
									? ''
									: 's'}</Card.Description
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
										>{#each data.users as client}<Table.Row
												><Table.Cell class="font-mono">{client}</Table.Cell><Table.Cell
													><form method="POST" use:enhanced action="?/deleteUser">
														<input type="hidden" name="csrf" value={data.csrf} /><input
															type="hidden"
															name="login"
															value={client}
														/><Button
															type="submit"
															size="icon"
															variant="ghost"
															aria-label={`Delete ${client}`}><Trash2 /></Button
														>
													</form></Table.Cell
												></Table.Row
											>{/each}</Table.Body
									></Table.Root
								>{:else}<Empty.Root
									><Empty.Header
										><Empty.Media variant="icon"><Inbox /></Empty.Media><Empty.Title
											>No SMTP clients</Empty.Title
										><Empty.Description
											>Add the first device or application login.</Empty.Description
										></Empty.Header
									></Empty.Root
								>{/if}</Card.Content
						></Card.Root
					>
				</div>
			</section>

			<section id="senders" class="section-block">
				<div class="section-heading">
					<div>
						<p class="eyebrow">03 · Identities</p>
						<h2>Allowed senders</h2>
					</div>
					<p>Restrict the From addresses each authenticated SMTP client may use.</p>
				</div>
				<div class="split-grid">
					<Card.Root
						><Card.Header
							><Card.Title>Allow sender</Card.Title><Card.Description
								>Changes are saved as pending until the relay configuration is applied.</Card.Description
							></Card.Header
						><Card.Content
							><form method="POST" use:enhanced action="?/allowSender">
								<input type="hidden" name="csrf" value={data.csrf} /><Field.FieldGroup
									><Field.Field
										><Field.FieldLabel for="sender_login">SMTP client</Field.FieldLabel><select
											id="sender_login"
											name="sender_login"
											class="native-control"
											required
											><option value="">Select a client</option>{#each data.users as client}<option
													value={client}>{client}</option
												>{/each}</select
										></Field.Field
									><Field.Field
										><Field.FieldLabel for="sender-address">From address</Field.FieldLabel><Input
											id="sender-address"
											name="from_addr"
											type="email"
											required
										/></Field.Field
									><Button type="submit">Allow sender</Button></Field.FieldGroup
								>
							</form></Card.Content
						></Card.Root
					><Card.Root
						><Card.Header
							><Card.Title>Sender policy</Card.Title><Card.Description
								>Explicit identities currently stored in configuration.</Card.Description
							></Card.Header
						><Card.Content
							>{#if Object.keys(data.config.allowed_from).length}<Table.Root
									><Table.Header
										><Table.Row
											><Table.Head>Client</Table.Head><Table.Head>Address</Table.Head><Table.Head
												>Default</Table.Head
											><Table.Head><span class="sr-only">Actions</span></Table.Head></Table.Row
										></Table.Header
									><Table.Body
										>{#each Object.entries(data.config.allowed_from) as [client, addresses]}{#each addresses as address}<Table.Row
													><Table.Cell>{client}</Table.Cell><Table.Cell>{address}</Table.Cell
													><Table.Cell
														>{#if data.config.default_from[client] === address}<Badge
																variant="secondary">Default</Badge
															>{:else}<form method="POST" use:enhanced action="?/setDefaultSender">
																<input type="hidden" name="csrf" value={data.csrf} /><input
																	type="hidden"
																	name="sender_login"
																	value={client}
																/><input type="hidden" name="from_addr" value={address} /><Button
																	type="submit"
																	size="sm"
																	variant="ghost">Make default</Button
																>
															</form>{/if}</Table.Cell
													><Table.Cell
														><form method="POST" use:enhanced action="?/disallowSender">
															<input type="hidden" name="csrf" value={data.csrf} /><input
																type="hidden"
																name="sender_login"
																value={client}
															/><input type="hidden" name="from_addr" value={address} /><Button
																type="submit"
																size="icon"
																variant="ghost"
																aria-label={`Remove ${address}`}><Trash2 /></Button
															>
														</form></Table.Cell
													></Table.Row
												>{/each}{/each}</Table.Body
									></Table.Root
								>{:else}<Empty.Root
									><Empty.Header
										><Empty.Title>No explicit sender policies</Empty.Title><Empty.Description
											>Add a client and sender address to enforce ownership.</Empty.Description
										></Empty.Header
									></Empty.Root
								>{/if}</Card.Content
						></Card.Root
					>
				</div>
			</section>

			<section id="oauth" class="section-block">
				<div class="section-heading">
					<div>
						<p class="eyebrow">04 · Authorization</p>
						<h2>Microsoft OAuth</h2>
					</div>
					<p>Obtain and refresh the token Postfix uses for outbound mail.</p>
				</div>
				<Card.Root
					><Card.Header
						><Card.Title>Device authorization</Card.Title><Card.Description
							>Configure tenant and client IDs above before starting.</Card.Description
						></Card.Header
					><Card.Content
						><div class="action-row">
							<form method="POST" use:enhanced action="?/startToken">
								<input type="hidden" name="csrf" value={data.csrf} /><Button type="submit"
									>Start device flow</Button
								>
							</form>
							<form method="POST" use:enhanced action="?/refreshToken">
								<input type="hidden" name="csrf" value={data.csrf} /><Button
									type="submit"
									variant="outline">Refresh token now</Button
								>
							</form>
						</div>
						<pre>{JSON.stringify(data.token, null, 2)}</pre>
						{#if data.deviceLog}<h3 class="log-heading">Device flow progress</h3>
							<pre>{data.deviceLog}</pre>{/if}</Card.Content
					></Card.Root
				>
			</section>

			<section id="delivery" class="section-block">
				<div class="section-heading">
					<div>
						<p class="eyebrow">05 · Verification</p>
						<h2>Delivery test</h2>
					</div>
					<p>Submit a message through the same local path used by connected clients.</p>
				</div>
				<Card.Root
					><Card.Header
						><Card.Title>Send test message</Card.Title><Card.Description
							>Acceptance confirms local submission; use logs below to confirm upstream delivery.</Card.Description
						></Card.Header
					><Card.Content
						><form method="POST" use:enhanced action="?/testMail">
							<input type="hidden" name="csrf" value={data.csrf} /><Field.FieldGroup
								><div class="form-grid">
									<Field.Field
										><Field.FieldLabel for="from_addr">From</Field.FieldLabel><Input
											id="from_addr"
											name="from_addr"
											type="email"
											value={data.config.ms365_smtp_user}
											required
										/></Field.Field
									><Field.Field
										><Field.FieldLabel for="to_addr">To</Field.FieldLabel><Input
											id="to_addr"
											name="to_addr"
											type="email"
											required
										/></Field.Field
									>
								</div>
								<Field.Field
									><Field.FieldLabel for="subject">Subject</Field.FieldLabel><Input
										id="subject"
										name="subject"
										value="Simple M365 Relay test"
									/></Field.Field
								><Field.Field
									><Field.FieldLabel for="body">Message</Field.FieldLabel><Textarea
										id="body"
										name="body"
										rows={4}
										value="This message verifies the Simple M365 Relay delivery path."
									/></Field.Field
								><Button type="submit">Send test message</Button></Field.FieldGroup
							>
						</form></Card.Content
					></Card.Root
				>
			</section>
			<section id="recovery" class="section-block">
				<div class="section-heading">
					<div>
						<p class="eyebrow">06 · Recovery</p>
						<h2>Backup and diagnostics</h2>
					</div>
					<p>Carry configuration between releases and collect redacted evidence for support.</p>
				</div>
				<div class="split-grid">
					<Card.Root
						><Card.Header
							><Card.Title>Portable backup</Card.Title><Card.Description
								>Contains relay configuration and SMTP client credentials. Store it securely.</Card.Description
							></Card.Header
						><Card.Content
							><div class="action-row">
								<Button href="/backup/export.zip"
									><Download data-icon="inline-start" />Download backup</Button
								><Button href="/diagnostics.txt" variant="outline">Download diagnostics</Button>
							</div></Card.Content
						></Card.Root
					><Card.Root
						><Card.Header
							><Card.Title>Restore archive</Card.Title><Card.Description
								>Accepts compatible v1 and v2 ZIP archives.</Card.Description
							></Card.Header
						><Card.Content
							><form
								method="POST"
								use:enhanced
								action="?/importBackup"
								enctype="multipart/form-data"
							>
								<input type="hidden" name="csrf" value={data.csrf} /><Field.FieldGroup
									><Field.Field
										><Field.FieldLabel for="backup">Backup ZIP</Field.FieldLabel><Input
											id="backup"
											name="backup"
											type="file"
											accept=".zip,application/zip"
											required
										/></Field.Field
									><Button type="submit" variant="outline">Import backup</Button></Field.FieldGroup
								>
							</form></Card.Content
						></Card.Root
					>
				</div>
			</section>
			<section id="logs" class="section-block">
				<div class="section-heading">
					<div>
						<p class="eyebrow">07 · Evidence</p>
						<h2>Queue and mail log</h2>
					</div>
					<p>
						Recent operational output with known token material redacted by the control service.
					</p>
				</div>
				<div class="split-grid">
					<Card.Root
						><Card.Header><Card.Title>Mail queue</Card.Title></Card.Header><Card.Content
							><pre>{data.queue || 'Mail queue is empty.'}</pre></Card.Content
						></Card.Root
					><Card.Root
						><Card.Header><Card.Title>Recent mail log</Card.Title></Card.Header><Card.Content
							><pre>{data.logs || 'No log entries yet.'}</pre></Card.Content
						></Card.Root
					>
				</div>
			</section>
		</main>{/snippet}</AppShell
>
