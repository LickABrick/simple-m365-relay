import { describe, expect, it } from 'vitest';
import {
	parseDeliveryDiagnostic,
	parseLog,
	parseQueue,
	summarizeOperationalProblems
} from './activity';

describe('activity parsers', () => {
	it('groups a Postfix queue record with its reason and recipient', () => {
		const queue = parseQueue(`-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
2FB501B47AC     626 Wed Aug 12 17:12:01  sender@example.com
(SASL authentication failed; server said: 535 5.7.3 Authentication unsuccessful)
                                         recipient@example.com

-- 0 Kbytes in 1 Request.`);
		expect(queue).toEqual([
			expect.objectContaining({
				id: '2FB501B47AC',
				sender: 'sender@example.com',
				recipients: ['recipient@example.com'],
				reason: expect.stringContaining('535 5.7.3')
			})
		]);
	});

	it('classifies delivery failures', () => {
		expect(
			parseLog('Aug 12 17:12:29 relay postfix/smtp[1]: SASL authentication failed')[0]
		).toMatchObject({ severity: 'error', service: 'postfix/smtp[1]' });
	});

	it('explains tenant-level SMTP AUTH policy failures without mistaking them for basic auth', () => {
		const message =
			'SASL authentication failed; server smtp.office365.com[40.99.205.2] said: 535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant.';
		expect(parseDeliveryDiagnostic(message)).toEqual(
			expect.objectContaining({
				code: '535 5.7.139',
				title: 'SMTP AUTH is disabled for this tenant',
				description: expect.stringContaining('using OAuth')
			})
		);
	});

	it('prioritizes active queue failures for the overview', () => {
		const problems = summarizeOperationalProblems(
			`2FB501B47AC     626 Wed Aug 12 17:12:01  sender@example.com
(SASL authentication failed)
                                         recipient@example.com`,
			'Aug 12 17:12:29 relay postfix/smtp[1]: warning: connection delayed'
		);
		expect(problems[0]).toMatchObject({
			source: 'queue',
			message: 'Exchange Online rejected OAuth authentication'
		});
		expect(problems[1]).toMatchObject({ source: 'log', severity: 'warning' });
	});
});
