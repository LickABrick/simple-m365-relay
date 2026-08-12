<script lang="ts">
	import { progressive } from '$lib/actions/progressive';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';
	import Download from '@lucide/svelte/icons/download';
	import Rotate from '@lucide/svelte/icons/rotate-cw';
	let { data } = $props();
</script>

<main class="console-page">
	<header class="console-heading">
		<div>
			<p class="command-path">~/system/recovery</p>
			<h1>Recovery</h1>
			<p>
				Move relay state safely, collect redacted evidence, or reload Postfix without changing
				configuration.
			</p>
		</div>
	</header>
	<div class="route-grid">
		<Card.Root
			><Card.Header
				><Card.Title>Portable backup</Card.Title><Card.Description
					>Configuration plus SMTP client credentials. OAuth tokens and the administrator are
					excluded.</Card.Description
				></Card.Header
			><Card.Footer
				><Button href="/backup/export.zip"><Download data-icon="inline-start" />Download ZIP</Button
				></Card.Footer
			></Card.Root
		><Card.Root
			><Card.Header
				><Card.Title>Redacted diagnostics</Card.Title><Card.Description
					>Configuration, health, token status, queue, and recent mail-log evidence.</Card.Description
				></Card.Header
			><Card.Footer
				><Button href="/diagnostics.txt" variant="outline">Download diagnostics</Button
				></Card.Footer
			></Card.Root
		>
	</div>
	<div class="two-panel">
		<Card.Root
			><Card.Header
				><Card.Title>Restore archive</Card.Title><Card.Description
					>Compatible v1/v2 backup ZIP, maximum 10 MB.</Card.Description
				></Card.Header
			><Card.Content
				><form method="POST" action="?/import" enctype="multipart/form-data" use:progressive>
					<input type="hidden" name="csrf" value={data.csrf} /><Field.FieldGroup
						><Field.Field
							><Field.FieldLabel for="backup">Backup ZIP</Field.FieldLabel><Input
								id="backup"
								name="backup"
								type="file"
								accept=".zip,application/zip"
								required
							/></Field.Field
						><Button type="submit">Import backup</Button></Field.FieldGroup
					>
				</form></Card.Content
			></Card.Root
		><Card.Root
			><Card.Header
				><Card.Title>Process control</Card.Title><Card.Description
					>Reload the currently rendered Postfix configuration. This does not save pending changes.</Card.Description
				></Card.Header
			><Card.Footer
				><form method="POST" action="?/reload" use:progressive>
					<input type="hidden" name="csrf" value={data.csrf} /><Button
						type="submit"
						variant="outline"><Rotate data-icon="inline-start" />Reload Postfix</Button
					>
				</form></Card.Footer
			></Card.Root
		>
	</div>
</main>
