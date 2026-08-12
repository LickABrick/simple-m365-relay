import type { RelayConfig } from './config';

export type ReadinessCheck = {
	id: 'relay' | 'network' | 'microsoft' | 'oauth' | 'client' | 'sender';
	label: string;
	href: string;
	complete: boolean;
};

export function evaluateReadiness(
	config: RelayConfig,
	options: { tokenPresent: boolean; users: string[] }
) {
	const senderCount = Object.values(config.allowed_from).reduce(
		(total, addresses) => total + addresses.length,
		0
	);
	const checks: ReadinessCheck[] = [
		{
			id: 'relay',
			label: 'Relay identity',
			href: '/onboarding/relay',
			complete: Boolean(config.hostname && config.domain && config.relayhost)
		},
		{
			id: 'network',
			label: 'Trust boundary',
			href: '/onboarding/network',
			complete: config.mynetworks.length > 0
		},
		{
			id: 'microsoft',
			label: 'Microsoft 365 application',
			href: '/onboarding/microsoft',
			complete: Boolean(config.ms365_smtp_user && config.oauth.tenant_id && config.oauth.client_id)
		},
		{
			id: 'oauth',
			label: 'OAuth authorization',
			href: '/onboarding/authorize',
			complete: options.tokenPresent
		},
		{
			id: 'client',
			label: 'SMTP client',
			href: '/onboarding/client',
			complete: options.users.length > 0
		},
		{
			id: 'sender',
			label: 'Sender policy',
			href: '/senders',
			complete: senderCount > 0
		}
	];
	const incomplete = checks.filter((check) => !check.complete);
	return {
		complete: incomplete.length === 0,
		checks,
		incomplete,
		completedCount: checks.length - incomplete.length,
		nextHref: incomplete[0]?.href || '/onboarding/review'
	};
}
