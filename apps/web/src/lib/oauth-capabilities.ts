import type { RelayConfig } from '$lib/server/config';

export type TokenIssue = {
	code: string;
	severity: 'warning' | 'error';
	message: string;
};

export type TokenStatus = {
	ok?: boolean;
	token_exp_ts?: number | null;
	token_type?: 'delegated' | 'application' | 'unknown';
	scopes?: string[];
	roles?: string[];
	smtp_scope_granted?: boolean | null;
	audience?: string;
	audience_ok?: boolean | null;
	identity?: string;
	tenant_id?: string;
	client_id?: string;
	has_refresh_token?: boolean;
	expired?: boolean;
	smtp_ready?: boolean;
	issues?: TokenIssue[];
	error?: string;
};

export type SenderCapability = {
	login: string;
	address: string;
	status: 'mailbox' | 'send-as-required';
	message: string;
};

export function analyzeOAuthCapabilities(config: RelayConfig, token: TokenStatus) {
	const mailbox = config.ms365_smtp_user.trim().toLowerCase();
	const tokenIdentity = (token.identity || '').trim().toLowerCase();
	const identityMismatch = Boolean(mailbox && tokenIdentity && mailbox !== tokenIdentity);
	const tenantMismatch = Boolean(
		config.oauth.tenant_id &&
		token.tenant_id &&
		config.oauth.tenant_id.toLowerCase() !== token.tenant_id.toLowerCase()
	);
	const clientMismatch = Boolean(
		config.oauth.client_id &&
		token.client_id &&
		config.oauth.client_id.toLowerCase() !== token.client_id.toLowerCase()
	);
	const configurationIssue = tenantMismatch
		? 'Token tenant does not match the configured tenant ID. Reauthorize after correcting the tenant.'
		: clientMismatch
			? 'Token application does not match the configured client ID. Reauthorize with the configured application.'
			: '';
	const senders: SenderCapability[] = Object.entries(config.allowed_from).flatMap(
		([login, addresses]) =>
			addresses.map((address) => {
				const normalized = address.trim().toLowerCase();
				if (normalized === mailbox && !identityMismatch)
					return {
						login,
						address,
						status: 'mailbox' as const,
						message: 'Matches the authenticated sending mailbox.'
					};
				return {
					login,
					address,
					status: 'send-as-required' as const,
					message: `${config.ms365_smtp_user || 'The sending mailbox'} needs Exchange Send As permission for this identity.`
				};
			})
	);
	const tokenIssues = token.issues || [];
	return {
		tokenPresent: token.ok === true,
		tokenReady:
			token.ok === true && token.smtp_ready === true && !tenantMismatch && !clientMismatch,
		identityMismatch,
		tenantMismatch,
		clientMismatch,
		configurationIssue,
		tokenIssues,
		senders,
		requiresSendAs: senders.filter((sender) => sender.status === 'send-as-required')
	};
}
