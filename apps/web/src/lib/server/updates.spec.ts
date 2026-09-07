import { describe, expect, it } from 'vitest';
import { compareVersions } from './updates';

describe('update version comparison', () => {
	it('treats the stable release as newer than its release candidate', () => {
		expect(compareVersions('2.0.0', '2.0.0-rc.1')).toBeGreaterThan(0);
	});

	it('orders numeric prerelease identifiers numerically', () => {
		expect(compareVersions('2.0.0-rc.10', '2.0.0-rc.2')).toBeGreaterThan(0);
	});

	it('ignores build metadata for precedence', () => {
		expect(compareVersions('2.0.0+build.2', '2.0.0+build.1')).toBe(0);
	});

	it('rejects partial versions instead of guessing', () => {
		expect(compareVersions('2.0', '1.9.9')).toBe(0);
	});
});
