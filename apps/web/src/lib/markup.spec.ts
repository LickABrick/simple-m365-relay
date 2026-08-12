import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'svelte/compiler';

const svelteFiles = (directory: string): string[] =>
	readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		const path = join(directory, entry.name);
		return entry.isDirectory() ? svelteFiles(path) : path.endsWith('.svelte') ? [path] : [];
	});

describe('application markup', () => {
	it('does not render standalone greater-than symbols from malformed component tags', () => {
		const offenders: string[] = [];
		for (const file of svelteFiles(join(process.cwd(), 'src/routes'))) {
			const source = readFileSync(file, 'utf8');
			const ast = parse(source, { modern: true });
			const visited = new Set<object>();
			const inspect = (node: unknown): void => {
				if (!node || typeof node !== 'object' || visited.has(node)) return;
				visited.add(node);
				if (
					'type' in node &&
					node.type === 'Text' &&
					'data' in node &&
					typeof node.data === 'string' &&
					node.data.trim() === '>'
				)
					offenders.push(file);
				for (const [key, value] of Object.entries(node)) {
					if (key === 'parent') continue;
					if (Array.isArray(value)) value.forEach(inspect);
					else inspect(value);
				}
			};
			inspect(ast.fragment);
		}
		expect(offenders).toEqual([]);
	});
});
