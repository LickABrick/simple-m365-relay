<script lang="ts">
	import './layout.css';
	import { Toaster } from '$lib/components/ui/sonner';
	import * as Tooltip from '$lib/components/ui/tooltip';
	let { children } = $props();
</script>

<svelte:head>
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="theme-color" content="#f7f9fc" />
	<title>Simple M365 Relay</title>
</svelte:head>
<Tooltip.Provider>
	{@render children()}
	<Toaster richColors closeButton />
</Tooltip.Provider>
