<script lang="ts">
	import AppShell from '$lib/components/app-shell.svelte';
	let { data, children } = $props();
</script>

<AppShell user={data.user} csrf={data.csrf} version={data.version}>{@render children()}</AppShell>
