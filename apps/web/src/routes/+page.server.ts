import { fail, redirect } from '@sveltejs/kit';
import { clearSession } from '$lib/server/auth';
import { control, parseUsers } from '$lib/server/control';
import {
	discardChanges,
	hasPendingChanges,
	loadConfig,
	markApplied,
	parseConfig,
	saveConfig
} from '$lib/server/config';
import type { Actions, PageServerLoad } from './$types';
import { configSchema } from '$lib/forms/schemas';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';

async function safe<T>(work: Promise<T>, fallback: T): Promise<T> {
	try {
		return await work;
	} catch {
		return fallback;
	}
}
function requireCsrf(form: FormData, expected: string | null) {
	if (!expected || String(form.get('csrf') || '') !== expected)
		throw new Error('Your session changed. Refresh the page and try again.');
}
const message = (error: unknown, fallback: string) =>
	error instanceof Error ? error.message : fallback;

export const load: PageServerLoad = async ({ locals }) => {
	const config = await loadConfig();
	const [health, queue, logs, token, rawUsers] = await Promise.all([
		safe(control<{ ok: boolean }>('/health'), { ok: false }),
		safe(control<{ mailq: string }>('/mailq'), { mailq: '' }),
		safe(control<{ maillog: string }>('/maillog'), { maillog: '' }),
		safe(control<Record<string, unknown>>('/token/status'), {}),
		safe(control<{ users: string }>('/users'), { users: '' })
	]);
	return {
		user: locals.user,
		csrf: locals.csrf,
		config,
		configForm: await superValidate(
			{
				csrf: locals.csrf || '',
				hostname: config.hostname,
				domain: config.domain,
				mynetworks: config.mynetworks.join('\n'),
				relayhost: config.relayhost,
				ms365_smtp_user: config.ms365_smtp_user,
				tls_25: config.tls.smtpd_25,
				tls_587: config.tls.smtpd_587,
				tenant_id: config.oauth.tenant_id,
				client_id: config.oauth.client_id,
				auto_refresh_minutes: config.oauth.auto_refresh_minutes
			},
			zod4(configSchema)
		),
		pending: await hasPendingChanges(config),
		health: health.ok,
		queue: queue.mailq,
		logs: logs.maillog,
		token,
		users: parseUsers(rawUsers.users),
		deviceLog: await safe(control<{ log: string }>('/device-flow-log'), { log: '' }).then(
			(value) => value.log
		),
		version: process.env.APP_VERSION || '2.0.0-rc.1'
	};
};

export const actions: Actions = {
	logout: async ({ request, cookies, locals }) => {
		const form = await request.formData();
		requireCsrf(form, locals.csrf);
		clearSession(cookies);
		redirect(303, '/login');
	},
	save: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(configSchema));
		try {
			if (!form.valid)
				return fail(400, {
					configForm: form,
					error: 'Review the highlighted configuration fields.'
				});
			const fields = new FormData();
			for (const [key, value] of Object.entries(form.data)) fields.set(key, String(value));
			fields.set('csrf', String(form.data.csrf || ''));
			requireCsrf(fields, locals.csrf);
			await saveConfig(parseConfig(fields, await loadConfig()));
			return { success: true, message: 'Configuration saved. Apply it when ready.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Configuration could not be saved.') });
		}
	},
	apply: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			const config = await loadConfig();
			await control('/render-validate', {});
			await control('/render-reload', {});
			await markApplied(config);
			return { success: true, message: 'Configuration validated and applied.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Configuration could not be applied.') });
		}
	},
	discard: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			await discardChanges();
			return { success: true, message: 'Saved changes were discarded.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Changes could not be discarded.') });
		}
	},
	addUser: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			await control('/users/add', {
				login: String(form.get('login') || '').trim(),
				password: String(form.get('password') || '')
			});
			return { success: true, message: 'SMTP client saved.' };
		} catch (e) {
			return fail(400, { error: message(e, 'SMTP client could not be saved.') });
		}
	},
	deleteUser: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			await control('/users/delete', { login: String(form.get('login') || '').trim() });
			return { success: true, message: 'SMTP client removed.' };
		} catch (e) {
			return fail(400, { error: message(e, 'SMTP client could not be removed.') });
		}
	},
	startToken: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			await control('/token/start', {});
			return { success: true, message: 'Microsoft device authorization started.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Authorization could not be started.') });
		}
	},
	refreshToken: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			await control('/token/refresh', {});
			return { success: true, message: 'Token refresh requested.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Token could not be refreshed.') });
		}
	},
	testMail: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			await control('/testmail', {
				to_addr: String(form.get('to_addr') || ''),
				from_addr: String(form.get('from_addr') || ''),
				subject: String(form.get('subject') || 'Relay test'),
				body: String(form.get('body') || 'Simple M365 Relay test message.')
			});
			return { success: true, message: 'Test message accepted by the relay.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Test message failed.') });
		}
	},
	allowSender: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			const login = String(form.get('sender_login') || '').trim();
			const address = String(form.get('from_addr') || '')
				.trim()
				.toLowerCase();
			if (!login || !/^\S+@\S+$/.test(address))
				throw new Error('Select a client and enter a valid sender address.');
			const config = await loadConfig();
			config.allowed_from[login] = [
				...new Set([...(config.allowed_from[login] || []), address])
			].sort();
			await saveConfig(config);
			return { success: true, message: 'Sender identity allowed.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Sender identity could not be saved.') });
		}
	},
	disallowSender: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			const login = String(form.get('sender_login') || '').trim();
			const address = String(form.get('from_addr') || '').trim();
			const config = await loadConfig();
			config.allowed_from[login] = (config.allowed_from[login] || []).filter(
				(entry) => entry !== address
			);
			if (!config.allowed_from[login].length) delete config.allowed_from[login];
			if (config.default_from[login] === address) delete config.default_from[login];
			await saveConfig(config);
			return { success: true, message: 'Sender identity removed.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Sender identity could not be removed.') });
		}
	},
	setDefaultSender: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			const login = String(form.get('sender_login') || '').trim();
			const address = String(form.get('from_addr') || '').trim();
			const config = await loadConfig();
			if (!(config.allowed_from[login] || []).includes(address))
				throw new Error('The default sender must already be allowed for this client.');
			config.default_from[login] = address;
			await saveConfig(config);
			return { success: true, message: 'Default sender updated.' };
		} catch (e) {
			return fail(400, { error: message(e, 'Default sender could not be updated.') });
		}
	},
	importBackup: async ({ request, locals }) => {
		const form = await request.formData();
		try {
			requireCsrf(form, locals.csrf);
			const file = form.get('backup');
			if (!(file instanceof File) || !file.size) throw new Error('Choose a backup ZIP file.');
			if (file.size > 10 * 1024 * 1024) throw new Error('Backup must be 10 MB or smaller.');
			await control('/backup/import', {
				zip_b64: Buffer.from(await file.arrayBuffer()).toString('base64')
			});
			return {
				success: true,
				message: 'Backup imported. Review and apply the restored configuration.'
			};
		} catch (e) {
			return fail(400, { error: message(e, 'Backup could not be imported.') });
		}
	}
};
