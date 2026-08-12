import { describe, expect, it } from 'vitest';
import { defaults, parseConfig } from './config';

function validForm(): FormData {
	const form = new FormData();
	for (const [key, value] of Object.entries({
		hostname: 'relay.example.test',
		domain: 'example.test',
		mynetworks: '127.0.0.0/8\n10.0.0.0/24',
		relayhost: '[smtp.office365.com]:587',
		tls_25: 'may',
		tls_587: 'encrypt',
		auto_refresh_minutes: '30'
	}))
		form.set(key, value);
	return form;
}

describe('parseConfig', () => {
	it('normalizes trusted network lines', () => {
		expect(parseConfig(validForm(), defaults).mynetworks).toEqual(['127.0.0.0/8', '10.0.0.0/24']);
	});
	it('rejects control characters', () => {
		const form = validForm();
		form.set('hostname', 'relay\nmalicious');
		expect(() => parseConfig(form, defaults)).toThrow(/Control characters/);
	});
	it('rejects unsafe refresh intervals', () => {
		const form = validForm();
		form.set('auto_refresh_minutes', '1441');
		expect(() => parseConfig(form, defaults)).toThrow(/0 to 1440/);
	});
});
