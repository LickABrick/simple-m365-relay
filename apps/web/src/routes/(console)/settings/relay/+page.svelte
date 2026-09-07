<script lang="ts">
	import { superForm } from 'sveltekit-superforms/client';
	import { zod4Client } from 'sveltekit-superforms/adapters';
	import { relaySettingsSchema } from '$lib/forms/schemas';
	import FormTextField from '$lib/components/form-text-field.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Badge } from '$lib/components/ui/badge';
	import { toast } from 'svelte-sonner';
	import ShieldCheck from '@lucide/svelte/icons/shield-check';
	import CircleCheck from '@lucide/svelte/icons/circle-check';
	import GitCompareArrows from '@lucide/svelte/icons/git-compare-arrows';
	import ProgressiveForm from '$lib/components/progressive-form.svelte';
	import { Spinner } from '$lib/components/ui/spinner';
	import * as Alert from '$lib/components/ui/alert';
	import { relayState } from '$lib/client/relay-state.svelte';
	import { untrack } from 'svelte';
	let { data } = $props();
	// svelte-ignore state_referenced_locally
	let pendingChanges = $state(data.pending);
	// svelte-ignore state_referenced_locally
	let configDiff = $state(data.diff);
	const settings = superForm(
		untrack(() => data.settingsForm),
		{
			validators: zod4Client(relaySettingsSchema),
			applyAction: false,
			invalidateAll: false,
			onResult: ({ result }) => {
				if (result.type === 'success') {
					const saved = (result.data as { form?: { data?: (typeof data.settingsForm)['data'] } })
						?.form?.data;
					if (saved) queueMicrotask(() => settings.reset({ data: saved, newState: saved }));
					const response = result.data as {
						message?: string;
						pending?: boolean;
						diff?: typeof data.diff;
					};
					pendingChanges = response.pending ?? true;
					configDiff = response.diff ?? configDiff;
					toast.success((result.data as { message?: string })?.message || 'Saved');
				} else if (result.type === 'failure')
					toast.error(
						(result.data as { error?: string })?.error || 'Relay settings could not be saved.'
					);
			}
		}
	);
	const { form, enhance, submitting, tainted } = settings;
	const changed = $derived(settings.isTainted($tainted));
</script>

<main class="console-page narrow-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/settings/relay</p>
			<h1>Relay identity</h1>
			<p>
				Define this relay and its Microsoft 365 upstream. Saving is intentionally separate from
				applying.
			</p>
		</div>
		{#if pendingChanges}<Badge variant="secondary">UNAPPLIED</Badge>{/if}
	</header>
	<Card.Root
		><Card.Header
			><Card.Title>Postfix identity</Card.Title><Card.Description
				>Values are validated in the browser and again on the server.</Card.Description
			></Card.Header
		><Card.Content>
			<form method="POST" action="?/save" use:enhance>
				<Field.FieldGroup>
					<input type="hidden" name="csrf" bind:value={$form.csrf} />
					<FormTextField
						form={settings}
						name="hostname"
						label="Relay hostname"
						description="Fully-qualified name advertised to SMTP clients."
					/>
					<FormTextField form={settings} name="domain" label="Local relay domain" />
					<FormTextField
						form={settings}
						name="relayhost"
						label="Upstream relay"
						description="Microsoft 365 normally uses [smtp.office365.com]:587."
					/>
					<Button type="submit" disabled={$submitting || !changed}
						>{#if $submitting}<Spinner data-icon="inline-start" />{/if}{$submitting
							? 'Saving…'
							: 'Save relay settings'}</Button
					>
				</Field.FieldGroup>
			</form>
		</Card.Content></Card.Root
	>
	<Card.Root id="deployment-review"
		><Card.Header
			><div class="deployment-heading">
				<div>
					<Card.Title>Deployment review</Card.Title><Card.Description
						>Compare saved settings with the running configuration before deployment.</Card.Description
					>
				</div>
				{#if pendingChanges}<Badge variant="secondary">{configDiff.length} CHANGED</Badge>{/if}
			</div>
		</Card.Header><Card.Content>
			{#if pendingChanges && configDiff.length > 0}
				<div class="config-diff" aria-label="Pending configuration changes">
					<div class="config-diff-header">
						<GitCompareArrows />
						<div>
							<strong>saved.sqlite → running.postfix</strong><span
								>{data.hasAppliedSnapshot ? 'Pending deployment' : 'Initial deployment'}</span
							>
						</div>
					</div>
					{#each configDiff as change}
						<div class="config-diff-hunk">
							<div class="config-diff-path">@@ {change.path} @@</div>
							<div class="config-diff-line removed"><span>−</span><code>{change.before}</code></div>
							<div class="config-diff-line added"><span>+</span><code>{change.after}</code></div>
						</div>
					{/each}
				</div>
			{:else}
				<Alert.Root>
					<CircleCheck />
					<Alert.Title>Running configuration is synchronized</Alert.Title>
					<Alert.Description>There are no saved changes waiting to be applied.</Alert.Description>
				</Alert.Root>
			{/if}
		</Card.Content>
		<Card.Footer class="deployment-footer">
			<p>
				Validate only performs a dry run. Validate &amp; apply repeats validation, renders, and
				reloads Postfix.
			</p>
			<div class="action-row">
				<ProgressiveForm
					method="POST"
					action="?/apply"
					onsucceeded={(response) => {
						pendingChanges = Boolean(response.pending);
						configDiff = (response.diff as typeof data.diff) || [];
					}}
				>
					{#snippet children(pending)}
						<input type="hidden" name="csrf" value={$form.csrf} /><Button
							type="submit"
							disabled={!pendingChanges || pending || !relayState.available}
							>{#if pending}<Spinner data-icon="inline-start" />{/if}{pending
								? 'Validating & applying…'
								: 'Validate & apply'}</Button
						>
					{/snippet}
				</ProgressiveForm>
				<ProgressiveForm method="POST" action="?/validate">
					{#snippet children(pending)}
						<input type="hidden" name="csrf" value={$form.csrf} /><Button
							type="submit"
							disabled={pending || !relayState.available}
							variant="outline"
							>{#if pending}<Spinner data-icon="inline-start" />{:else}<ShieldCheck
									data-icon="inline-start"
								/>{/if}{pending ? 'Validating…' : 'Validate only'}</Button
						>
					{/snippet}
				</ProgressiveForm>
				<ProgressiveForm
					method="POST"
					action="?/discard"
					onsucceeded={(response) => {
						pendingChanges = Boolean(response.pending);
						configDiff = (response.diff as typeof data.diff) || [];
					}}
				>
					{#snippet children(pending)}
						<input type="hidden" name="csrf" value={$form.csrf} /><Button
							type="submit"
							variant="ghost"
							disabled={!pendingChanges || pending}
							>{#if pending}<Spinner data-icon="inline-start" />{/if}{pending
								? 'Discarding…'
								: 'Discard'}</Button
						>
					{/snippet}
				</ProgressiveForm>
			</div>
		</Card.Footer></Card.Root
	>
</main>
