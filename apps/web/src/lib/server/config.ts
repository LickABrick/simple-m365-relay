import { stableHash } from './files';
import { db } from './database';
import { settings } from './schema';

export type RelayConfig = {
	hostname: string;
	domain: string;
	mynetworks: string[];
	relayhost: string;
	ms365_smtp_user: string;
	tls: { smtpd_25: 'none' | 'may' | 'encrypt'; smtpd_587: 'none' | 'may' | 'encrypt' };
	oauth: { tenant_id: string; client_id: string; auto_refresh_minutes: number };
	allowed_from: Record<string, string[]>;
	default_from: Record<string, string>;
	onboarding_complete?: boolean;
};

export const defaults: RelayConfig = {
	hostname: 'relay.local',
	domain: 'local',
	mynetworks: ['127.0.0.0/8'],
	relayhost: '[smtp.office365.com]:587',
	ms365_smtp_user: '',
	tls: { smtpd_25: 'may', smtpd_587: 'encrypt' },
	oauth: { tenant_id: '', client_id: '', auto_refresh_minutes: 30 },
	allowed_from: {},
	default_from: {}
};

export type ConfigDiffEntry = {
	path: string;
	before: string;
	after: string;
};

const deploymentConfig = (config: RelayConfig): Omit<RelayConfig, 'onboarding_complete'> => {
	const { onboarding_complete: _onboardingComplete, ...deployable } = config;
	return deployable;
};

const pathFor = (parent: string, key: string) =>
	parent
		? /^[A-Za-z_][A-Za-z0-9_]*$/.test(key)
			? `${parent}.${key}`
			: `${parent}[${JSON.stringify(key)}]`
		: key;

const flattenConfig = (value: unknown, parent = '', output = new Map<string, unknown>()) => {
	if (Array.isArray(value)) {
		output.set(parent, value);
		return output;
	}
	if (value !== null && typeof value === 'object') {
		for (const [key, child] of Object.entries(value).sort(([left], [right]) =>
			left.localeCompare(right)
		))
			flattenConfig(child, pathFor(parent, key), output);
		return output;
	}
	output.set(parent, value);
	return output;
};

const displayConfigValue = (path: string, value: unknown) => {
	if (/(?:^|\.)(?:password|secret|token)(?:$|\.)/i.test(path)) return '"[redacted]"';
	if (value === undefined) return '(not set)';
	return JSON.stringify(value);
};

export function diffConfig(applied: RelayConfig | null, saved: RelayConfig): ConfigDiffEntry[] {
	const before = flattenConfig(applied ? deploymentConfig(applied) : {});
	const after = flattenConfig(deploymentConfig(saved));
	const paths = [...new Set([...before.keys(), ...after.keys()])].sort();
	return paths.flatMap((path) => {
		const previous = before.get(path);
		const next = after.get(path);
		if (JSON.stringify(previous) === JSON.stringify(next)) return [];
		return [
			{
				path,
				before: displayConfigValue(path, previous),
				after: displayConfigValue(path, next)
			}
		];
	});
}

export async function loadAppliedConfig(): Promise<RelayConfig | null> {
	return (
		(db.select({ config: settings.appliedConfig }).from(settings).get()
			?.config as RelayConfig | null) || null
	);
}

export async function loadConfig(): Promise<RelayConfig> {
	const stored = (db.select().from(settings).get()?.config || {}) as Partial<RelayConfig>;
	return {
		...defaults,
		...stored,
		tls: { ...defaults.tls, ...stored.tls },
		oauth: { ...defaults.oauth, ...stored.oauth },
		allowed_from: stored.allowed_from || {},
		default_from: stored.default_from || {}
	};
}

export async function saveConfig(config: RelayConfig): Promise<void> {
	const updatedAt = Math.floor(Date.now() / 1000);
	db.insert(settings)
		.values({ id: 1, config, updatedAt })
		.onConflictDoUpdate({ target: settings.id, set: { config, updatedAt } })
		.run();
}

export async function hasPendingChanges(config: RelayConfig): Promise<boolean> {
	const applied = await loadAppliedConfig();
	return !applied || diffConfig(applied, config).length > 0;
}

export async function markApplied(config: RelayConfig): Promise<void> {
	db.update(settings)
		.set({
			appliedHash: stableHash(deploymentConfig(config)),
			appliedConfig: config,
			updatedAt: Math.floor(Date.now() / 1000)
		})
		.run();
}

export async function discardChanges(): Promise<RelayConfig> {
	const applied = await loadAppliedConfig();
	if (!applied) throw new Error('No applied configuration snapshot is available.');
	await saveConfig(applied);
	return applied;
}

export function parseConfig(form: FormData, current: RelayConfig): RelayConfig {
	const text = (name: string, fallback = '') => String(form.get(name) ?? fallback).trim();
	const rejectControl = (value: string) => {
		if (
			[...value].some(
				(character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127
			)
		)
			throw new Error('Control characters are not allowed.');
		return value;
	};
	const hostname = rejectControl(text('hostname', current.hostname));
	const domain = rejectControl(text('domain', current.domain));
	const relayhost = rejectControl(text('relayhost', current.relayhost));
	if (
		!hostname ||
		!domain ||
		!relayhost ||
		hostname.length > 253 ||
		domain.length > 253 ||
		relayhost.length > 512
	)
		throw new Error('Relay identity fields are invalid.');
	const mynetworks = text('mynetworks', current.mynetworks.join('\n'))
		.split(/[\s,]+/)
		.filter(Boolean);
	if (
		!mynetworks.length ||
		mynetworks.length > 128 ||
		mynetworks.some((v) => v.length > 128 || /[^0-9a-fA-F:./]/.test(v))
	)
		throw new Error('Trusted networks must be valid CIDR-style entries.');
	const tls = (name: string, fallback: RelayConfig['tls']['smtpd_25']) => {
		const value = text(name, fallback);
		if (!['none', 'may', 'encrypt'].includes(value)) throw new Error('Invalid TLS policy.');
		return value as RelayConfig['tls']['smtpd_25'];
	};
	const refresh = Number.parseInt(
		text('auto_refresh_minutes', String(current.oauth.auto_refresh_minutes)),
		10
	);
	if (!Number.isInteger(refresh) || refresh < 0 || refresh > 1440)
		throw new Error('Refresh interval must be from 0 to 1440 minutes.');
	return {
		...current,
		hostname,
		domain,
		mynetworks,
		relayhost,
		ms365_smtp_user: rejectControl(text('ms365_smtp_user')),
		tls: {
			smtpd_25: tls('tls_25', current.tls.smtpd_25),
			smtpd_587: tls('tls_587', current.tls.smtpd_587)
		},
		oauth: {
			tenant_id: rejectControl(text('tenant_id')),
			client_id: rejectControl(text('client_id')),
			auto_refresh_minutes: refresh
		}
	};
}
