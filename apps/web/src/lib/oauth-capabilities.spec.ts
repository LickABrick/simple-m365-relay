import { describe, expect, it } from 'vitest';
import { defaults } from '$lib/server/config';
import { analyzeOAuthCapabilities } from './oauth-capabilities';

const config = {
	...defaults,
	ms365_smtp_user: 'relay@example.com',
	allowed_from: { printer: ['relay@example.com', 'invoices@example.com'] }
};

describe('analyzeOAuthCapabilities', () => {
	it('separates the authenticated mailbox from identities requiring Send As', () => {
		const result = analyzeOAuthCapabilities(config, {
			ok: true,
			smtp_ready: true,
			identity: 'relay@example.com'
		});
		expect(result.tokenReady).toBe(true);
		expect(result.senders.map((sender) => sender.status)).toEqual(['mailbox', 'send-as-required']);
	});

	it('requires Send As verification without rejecting a valid delegated mailbox token', () => {
		const result = analyzeOAuthCapabilities(config, {
			ok: true,
			smtp_ready: true,
			identity: 'other@example.com'
		});
		expect(result.tokenReady).toBe(true);
		expect(result.identityMismatch).toBe(true);
		expect(result.senders.every((sender) => sender.status === 'send-as-required')).toBe(true);
	});

	it('rejects a token issued to another configured application', () => {
		const result = analyzeOAuthCapabilities(
			{ ...config, oauth: { ...config.oauth, client_id: 'expected-client' } },
			{ ok: true, smtp_ready: true, client_id: 'other-client' }
		);
		expect(result.tokenReady).toBe(false);
		expect(result.clientMismatch).toBe(true);
	});
});
