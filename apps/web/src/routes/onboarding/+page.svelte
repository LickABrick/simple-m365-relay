<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import Check from '@lucide/svelte/icons/check';
	import Arrow from '@lucide/svelte/icons/arrow-right';
	let { data } = $props();
</script>

<main class="onboarding-shell">
	<header class="onboarding-heading">
		<p class="command-path">INITIALIZATION SEQUENCE</p>
		<h1>Bring the relay online.</h1>
		<p>
			Six focused checks. Progress is derived from saved state, so you can leave and continue later.
		</p>
	</header>
	<section class="onboarding-index">
		{#each data.steps as step, index}<a href={step.href}
				><span class="step-index">0{index + 1}</span>
				<div>
					<strong>{step.label}</strong><small>{step.complete ? 'Ready' : 'Action required'}</small>
				</div>
				{#if step.complete}<Badge><Check />Complete</Badge>{:else}<Arrow />
				{/if}</a
			>{/each}
	</section>
	<Card.Root
		><Card.Header
			><Card.Title>Current readiness</Card.Title><Card.Description
				>The control service is {data.health ? 'reachable' : 'not reachable'}. {data.steps.filter(
					(s) => s.complete
				).length} of {data.steps.length} checks are complete.</Card.Description
			></Card.Header
		><Card.Footer
			><Button href={data.steps.find((s) => !s.complete)?.href || '/onboarding/review'}
				>Continue setup<Arrow data-icon="inline-end" /></Button
			><Button href="/overview" variant="ghost">Exit to overview</Button></Card.Footer
		></Card.Root
	>
</main>
