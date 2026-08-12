import { fail, redirect, error } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod4 } from 'sveltekit-superforms/adapters';
import {
	microsoftSettingsSchema,
	networkSettingsSchema,
	relaySettingsSchema,
	smtpClientSchema
} from '$lib/forms/schemas';
import { loadConfig, markApplied, saveConfig } from '$lib/server/config';
import { control, parseUsers } from '$lib/server/control';
import { requireCsrf, setOnboardingComplete, errorMessage } from '$lib/server/operations';
import type { Actions, PageServerLoad } from './$types';
import { analyzeOAuthCapabilities, type TokenStatus } from '$lib/oauth-capabilities';
const valid = new Set(['relay', 'network', 'microsoft', 'authorize', 'client', 'review']);
export const load: PageServerLoad = async ({ params, locals }) => {
	if (!valid.has(params.step)) error(404);
	const config = await loadConfig();
	const token = await control<TokenStatus>('/token/status').catch((): TokenStatus => ({}));
	return {
		step: params.step,
		csrf: locals.csrf,
		config,
		health: await control<{ ok: boolean }>('/health')
			.then((value) => value.ok)
			.catch(() => false),
		token,
		capabilities: analyzeOAuthCapabilities(config, token),
		deviceLog: await control<{ log: string }>('/device-flow-log')
			.then((v) => v.log)
			.catch(() => ''),
		users: await control<{ users: string }>('/users')
			.then((v) => parseUsers(v.users))
			.catch(() => []),
		senderCount: Object.values(config.allowed_from).reduce(
			(total, addresses) => total + addresses.length,
			0
		),
		relayForm: await superValidate(
			{
				csrf: locals.csrf || '',
				hostname: config.hostname,
				domain: config.domain,
				relayhost: config.relayhost
			},
			zod4(relaySettingsSchema)
		),
		networkForm: await superValidate(
			{
				csrf: locals.csrf || '',
				mynetworks: config.mynetworks.join('\n'),
				tls_25: config.tls.smtpd_25,
				tls_587: config.tls.smtpd_587
			},
			zod4(networkSettingsSchema)
		),
		microsoftForm: await superValidate(
			{
				csrf: locals.csrf || '',
				ms365_smtp_user: config.ms365_smtp_user,
				tenant_id: config.oauth.tenant_id,
				client_id: config.oauth.client_id,
				auto_refresh_minutes: config.oauth.auto_refresh_minutes
			},
			zod4(microsoftSettingsSchema)
		),
		clientForm: await superValidate(
			{ csrf: locals.csrf || '', login: '', password: '' },
			zod4(smtpClientSchema)
		)
	};
};
export const actions: Actions = {
	save: async ({ request, locals, params }) => {
		let submittedForm: unknown;
		try {
			const c = await loadConfig();
			if (params.step === 'relay') {
				const form = await superValidate(request, zod4(relaySettingsSchema));
				submittedForm = form;
				if (!form.valid) return fail(400, { form });
				const f = new FormData();
				f.set('csrf', form.data.csrf);
				requireCsrf(f, locals.csrf);
				c.hostname = form.data.hostname;
				c.domain = form.data.domain;
				c.relayhost = form.data.relayhost;
			} else if (params.step === 'network') {
				const form = await superValidate(request, zod4(networkSettingsSchema));
				submittedForm = form;
				if (!form.valid) return fail(400, { form });
				const f = new FormData();
				f.set('csrf', form.data.csrf);
				requireCsrf(f, locals.csrf);
				const n = form.data.mynetworks.split(/[\s,]+/).filter(Boolean);
				if (!n.length || n.some((v) => /[^0-9a-fA-F:./]/.test(v)))
					throw new Error('Enter valid CIDR-style trusted networks.');
				c.mynetworks = n;
				c.tls = {
					smtpd_25: form.data.tls_25,
					smtpd_587: form.data.tls_587
				};
			} else if (params.step === 'microsoft') {
				const form = await superValidate(request, zod4(microsoftSettingsSchema));
				submittedForm = form;
				if (!form.valid) return fail(400, { form });
				const f = new FormData();
				f.set('csrf', form.data.csrf);
				requireCsrf(f, locals.csrf);
				c.ms365_smtp_user = form.data.ms365_smtp_user;
				c.oauth = {
					tenant_id: form.data.tenant_id,
					client_id: form.data.client_id,
					auto_refresh_minutes: form.data.auto_refresh_minutes
				};
			} else throw new Error('This step has no settings form.');
			await saveConfig(c);
			const next: { [key: string]: string } = {
				relay: 'network',
				network: 'microsoft',
				microsoft: 'authorize'
			};
			redirect(303, `/onboarding/${next[params.step]}`);
		} catch (e) {
			if (e && typeof e === 'object' && 'status' in e) throw e;
			return fail(400, {
				form: submittedForm,
				error: errorMessage(e, 'Settings could not be saved.')
			});
		}
	},
	start: async ({ request, locals }) => {
		const f = await request.formData();
		try {
			requireCsrf(f, locals.csrf);
			await control('/token/start', {});
			return { success: true, message: 'Authorization started.' };
		} catch (e) {
			return fail(400, { error: errorMessage(e, 'Authorization could not start.') });
		}
	},
	client: async ({ request, locals }) => {
		const form = await superValidate(request, zod4(smtpClientSchema));
		if (!form.valid) return fail(400, { form });
		try {
			const f = new FormData();
			f.set('csrf', form.data.csrf);
			requireCsrf(f, locals.csrf);
			await control('/users/add', { login: form.data.login, password: form.data.password });
			redirect(303, '/onboarding/review');
		} catch (e) {
			if (e && typeof e === 'object' && 'status' in e) throw e;
			return fail(400, { form, error: errorMessage(e, 'Client could not be saved.') });
		}
	},
	finish: async ({ request, locals }) => {
		const f = await request.formData();
		try {
			requireCsrf(f, locals.csrf);
			const c = await loadConfig();
			if (!c.ms365_smtp_user || !c.oauth.tenant_id || !c.oauth.client_id)
				throw new Error('Microsoft 365 configuration is incomplete.');
			const [health, token, users] = await Promise.all([
				control<{ ok: boolean }>('/health'),
				control<TokenStatus>('/token/status'),
				control<{ users: string }>('/users')
			]);
			if (!health.ok) throw new Error('The relay control service is unavailable.');
			const capabilities = analyzeOAuthCapabilities(c, token);
			if (!capabilities.tokenReady)
				throw new Error(
					capabilities.configurationIssue ||
						token.issues?.[0]?.message ||
						'Complete Microsoft authorization with SMTP.Send first.'
				);
			if (!parseUsers(users.users).length)
				throw new Error('Create at least one SMTP client first.');
			if (!Object.values(c.allowed_from).some((addresses) => addresses.length > 0))
				throw new Error('Allow at least one sender identity first.');
			await setOnboardingComplete();
			const completed = await loadConfig();
			await control('/render-validate', {});
			await control('/render-reload', {});
			await markApplied(completed);
			redirect(303, '/overview');
		} catch (e) {
			if (e && typeof e === 'object' && 'status' in e) throw e;
			return fail(400, { error: errorMessage(e, 'Relay is not ready to finish setup.') });
		}
	}
};
