import { fail, type RequestEvent } from '@sveltejs/kit';
import { control, parseUsers } from './control';
import { discardChanges, hasPendingChanges, loadConfig, markApplied, saveConfig } from './config';
import { evaluateReadiness } from './readiness';

export const errorMessage = (error: unknown, fallback: string) =>
	error instanceof Error ? error.message : fallback;

export function requireCsrf(form: FormData, expected: string | null): void {
	if (!expected || String(form.get('csrf') || '') !== expected)
		throw new Error('Your session changed. Refresh this page and try again.');
}

export async function getOverview() {
	const safe = async <T>(work: Promise<T>, fallback: T): Promise<T> => {
		try {
			return await work;
		} catch {
			return fallback;
		}
	};
	const [health, queue, token, users] = await Promise.all([
		safe(control<{ ok: boolean }>('/health'), { ok: false }),
		safe(control<{ mailq: string }>('/mailq'), { mailq: '' }),
		safe(control<Record<string, unknown>>('/token/status'), {}),
		safe(control<{ users: string }>('/users'), { users: '' })
	]);
	return {
		health: health.ok,
		queue: queue.mailq,
		token,
		users: parseUsers(users.users)
	};
}

export async function getActivity() {
	const [queue, log] = await Promise.all([
		control<{ mailq: string }>('/mailq').catch(() => ({ mailq: '' })),
		control<{ maillog: string }>('/maillog').catch(() => ({ maillog: '' }))
	]);
	return { queue: queue.mailq, logs: log.maillog };
}

export async function getMicrosoftState() {
	const [token, deviceLog, refreshLog] = await Promise.all([
		control<Record<string, unknown>>('/token/status').catch(() => ({})),
		control<{ log: string }>('/device-flow-log').catch(() => ({ log: '' })),
		control<{ log: string }>('/token/refresh-log').catch(() => ({ log: '' }))
	]);
	return { token, deviceLog: deviceLog.log, refreshLog: refreshLog.log };
}

export async function getRelayHealth() {
	return control<{ ok: boolean }>('/health').catch(() => ({ ok: false }));
}

export async function getConsoleStatus() {
	const config = await loadConfig();
	const [health, token, users] = await Promise.all([
		control<{ ok: boolean }>('/health').catch(() => ({ ok: false })),
		control<Record<string, unknown>>('/token/status').catch((): Record<string, unknown> => ({})),
		control<{ users: string }>('/users').catch(() => ({ users: '' }))
	]);
	return {
		relayAvailable: health.ok,
		readiness: evaluateReadiness(config, {
			tokenPresent: token['ok'] === true,
			users: parseUsers(users.users)
		}),
		pendingChanges: await hasPendingChanges(config)
	};
}

export const applyAction = async ({ request, locals }: RequestEvent) => {
	const form = await request.formData();
	try {
		requireCsrf(form, locals.csrf);
		const config = await loadConfig();
		await control('/render-validate', {});
		await control('/render-reload', {});
		await markApplied(config);
		return { success: true, message: 'Configuration validated and applied.' };
	} catch (error) {
		return fail(400, { error: errorMessage(error, 'Configuration could not be applied.') });
	}
};

export const validateAction = async ({ request, locals }: RequestEvent) => {
	const form = await request.formData();
	try {
		requireCsrf(form, locals.csrf);
		await control('/render-validate', {});
		return { success: true, message: 'Saved configuration passed Postfix validation.' };
	} catch (error) {
		return fail(400, { error: errorMessage(error, 'Configuration validation failed.') });
	}
};

export const discardAction = async ({ request, locals }: RequestEvent) => {
	const form = await request.formData();
	try {
		requireCsrf(form, locals.csrf);
		await discardChanges();
		return { success: true, message: 'Saved changes were discarded.' };
	} catch (error) {
		return fail(400, { error: errorMessage(error, 'Changes could not be discarded.') });
	}
};

export const reloadAction = async ({ request, locals }: RequestEvent) => {
	const form = await request.formData();
	try {
		requireCsrf(form, locals.csrf);
		await control('/render-reload', {});
		return { success: true, message: 'Postfix reloaded.' };
	} catch (error) {
		return fail(400, { error: errorMessage(error, 'Postfix could not be reloaded.') });
	}
};

export async function setOnboardingComplete(): Promise<void> {
	const config = await loadConfig();
	config.onboarding_complete = true;
	await saveConfig(config);
}
