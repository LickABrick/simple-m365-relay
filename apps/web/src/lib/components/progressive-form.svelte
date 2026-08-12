<script lang="ts">
	import { enhance } from '$app/forms';
	import { toast } from 'svelte-sonner';
	import type { Snippet } from 'svelte';
	import type { HTMLFormAttributes } from 'svelte/elements';

	let {
		children,
		successMessage,
		reset = false,
		invalidateAll = false,
		onsucceeded,
		onfailed,
		...formProps
	}: Omit<HTMLFormAttributes, 'children'> & {
		children: Snippet<[pending: boolean]>;
		successMessage?: string;
		reset?: boolean;
		invalidateAll?: boolean;
		onsucceeded?: (data: Record<string, unknown>) => void;
		onfailed?: (message: string) => void;
	} = $props();

	let pending = $state(false);

	const useProgressive = (node: HTMLFormElement) =>
		enhance(node, () => {
			if (pending) return () => undefined;
			pending = true;
			return async ({ result, update }) => {
				try {
					await update({ invalidateAll, reset: reset && result.type === 'success' });
					if (result.type === 'success') {
						const data = (result.data || {}) as Record<string, unknown>;
						const message = String(data.message || successMessage || 'Operation completed.');
						toast.success(message);
						onsucceeded?.(data);
					} else if (result.type === 'failure') {
						const message = String(
							(result.data as { error?: string } | undefined)?.error || 'The operation failed.'
						);
						toast.error(message);
						onfailed?.(message);
					} else if (result.type === 'error') {
						const message = result.error.message || 'The operation failed.';
						toast.error(message);
						onfailed?.(message);
					}
				} finally {
					pending = false;
				}
			};
		});
</script>

<form {...formProps} use:useProgressive aria-busy={pending}>
	{@render children(pending)}
</form>
