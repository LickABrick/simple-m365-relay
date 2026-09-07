<script lang="ts">
	import type { DeliveryDiagnostic } from '$lib/activity';
	import * as Alert from '$lib/components/ui/alert';
	import { Badge } from '$lib/components/ui/badge';
	import ExternalLink from '@lucide/svelte/icons/external-link';

	let { diagnostic, raw }: { diagnostic: DeliveryDiagnostic; raw: string } = $props();
</script>

<Alert.Root variant="destructive" class="delivery-diagnostic">
	<div class="delivery-diagnostic-heading">
		<Alert.Title>{diagnostic.title}</Alert.Title>
		{#if diagnostic.code}<Badge variant="outline">{diagnostic.code}</Badge>{/if}
	</div>
	<Alert.Description>{diagnostic.description}</Alert.Description>
	<div class="delivery-diagnostic-actions">
		{#if diagnostic.referenceUrl}
			<a href={diagnostic.referenceUrl} target="_blank" rel="noreferrer">
				Microsoft guidance <ExternalLink />
			</a>
		{/if}
		<details>
			<summary>Technical detail</summary>
			<p>{raw}</p>
		</details>
	</div>
</Alert.Root>
