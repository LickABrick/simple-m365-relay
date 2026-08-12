<script
	lang="ts"
	generics="T extends Record<string, unknown>, U extends import('sveltekit-superforms').FormPathLeaves<T, string>"
>
	import { Control, Field as FormField, FieldErrors, Label } from 'formsnap';
	import { formFieldProxy, type SuperForm } from 'sveltekit-superforms';
	import type { HTMLInputAttributes } from 'svelte/elements';
	import * as Field from '$lib/components/ui/field';
	import { Input } from '$lib/components/ui/input';

	let {
		form,
		name,
		label,
		type = 'text',
		autocomplete,
		autofocus = false,
		required = true,
		description
	}: {
		form: SuperForm<T>;
		name: U;
		label: string;
		type?: string;
		autocomplete?: HTMLInputAttributes['autocomplete'];
		autofocus?: boolean;
		required?: boolean;
		description?: string;
	} = $props();

	// svelte-ignore state_referenced_locally
	const { value: fieldValue } = formFieldProxy<T, U, string>(form, name);
</script>

<FormField {form} {name}>
	{#snippet children({ errors })}
		<Field.Field data-invalid={Boolean(errors?.length)}>
			<Control>
				{#snippet children({ props })}
					<Label><Field.FieldLabel>{label}</Field.FieldLabel></Label>
					<Input
						{...props}
						{type}
						{autocomplete}
						{autofocus}
						{required}
						aria-invalid={Boolean(errors?.length)}
						bind:value={$fieldValue}
					/>
				{/snippet}
			</Control>
			{#if description}<Field.FieldDescription>{description}</Field.FieldDescription>{/if}
			<FieldErrors>
				{#snippet children()}<Field.FieldError>{errors}</Field.FieldError>{/snippet}
			</FieldErrors>
		</Field.Field>
	{/snippet}
</FormField>
