import { describe, expect, it } from 'vitest';
import { defaults } from './config';
import { evaluateReadiness } from './readiness';

describe('evaluateReadiness', () => {
	it('requires OAuth, an SMTP client, and an allowed sender', () => {
		const result = evaluateReadiness(defaults, { tokenPresent: false, users: [] });
		expect(result.complete).toBe(false);
		expect(result.incomplete.map((check) => check.id)).toEqual([
			'microsoft',
			'oauth',
			'client',
			'sender'
		]);
	});

	it('is complete only when every operational prerequisite is present', () => {
		const config = {
			...defaults,
			ms365_smtp_user: 'relay@example.com',
			oauth: { ...defaults.oauth, tenant_id: 'tenant', client_id: 'client' },
			allowed_from: { device: ['relay@example.com'] }
		};
		const result = evaluateReadiness(config, { tokenPresent: true, users: ['device'] });
		expect(result.complete).toBe(true);
		expect(result.completedCount).toBe(result.checks.length);
	});

	it('does not accept a merely present token when its SMTP capability is invalid', () => {
		const config = {
			...defaults,
			ms365_smtp_user: 'relay@example.com',
			oauth: { ...defaults.oauth, tenant_id: 'tenant', client_id: 'client' },
			allowed_from: { device: ['relay@example.com'] }
		};
		const result = evaluateReadiness(config, {
			tokenPresent: true,
			tokenReady: false,
			users: ['device']
		});
		expect(result.incomplete.map((check) => check.id)).toContain('oauth');
	});
});
