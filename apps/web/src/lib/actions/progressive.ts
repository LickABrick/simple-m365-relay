import { enhance } from '$app/forms';
import { invalidateAll } from '$app/navigation';
import { toast } from 'svelte-sonner';
import type { Action } from 'svelte/action';

export const progressive: Action<HTMLFormElement> = (node) =>
	enhance(node, () => async ({ result, update }) => {
		await update({ invalidateAll: false, reset: result.type === 'success' });
		if (result.type === 'success') {
			const payload = result.data as { message?: string } | undefined;
			toast.success(payload?.message || 'Done');
			await invalidateAll();
		} else if (result.type === 'failure') {
			const payload = result.data as { error?: string } | undefined;
			toast.error(payload?.error || 'The operation failed.');
		} else if (result.type === 'error')
			toast.error(result.error.message || 'The operation failed.');
	});
