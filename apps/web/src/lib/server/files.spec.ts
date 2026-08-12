import { describe, expect, it } from 'vitest';
import { stableHash } from './files';

describe('stableHash', () => {
	it('is independent of object key order', () => {
		expect(stableHash({ b: 2, a: { d: 4, c: 3 } })).toBe(stableHash({ a: { c: 3, d: 4 }, b: 2 }));
	});
});
