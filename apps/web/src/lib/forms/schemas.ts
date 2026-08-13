import { z } from 'zod';
export const username = z
	.string()
	.trim()
	.min(1)
	.max(64)
	.regex(/^[A-Za-z0-9._-]+$/, 'Use letters, numbers, dots, underscores, or dashes.');
export const strongPassword = z
	.string()
	.min(12, 'Use at least 12 characters.')
	.regex(/[a-z]/, 'Include a lower-case letter.')
	.regex(/[A-Z]/, 'Include an upper-case letter.')
	.regex(/\d/, 'Include a number.')
	.regex(/[^A-Za-z0-9]/, 'Include a symbol.');
export const loginSchema = z.object({
	username,
	password: z.string().min(1, 'Enter your password.')
});
export const setupSchema = z
	.object({ username, password: strongPassword, confirm: z.string() })
	.refine((value) => value.password === value.confirm, {
		message: 'The passwords do not match.',
		path: ['confirm']
	});
export const changePasswordSchema = z
	.object({
		csrf: z.string().min(1),
		currentPassword: z.string().min(1, 'Enter your current password.'),
		password: strongPassword,
		confirm: z.string()
	})
	.refine((value) => value.password === value.confirm, {
		message: 'The passwords do not match.',
		path: ['confirm']
	});
export const configSchema = z.object({
	csrf: z.string().min(1),
	hostname: z.string().trim().min(1).max(253),
	domain: z.string().trim().min(1).max(253),
	mynetworks: z.string().trim().min(1),
	relayhost: z.string().trim().min(1).max(512),
	ms365_smtp_user: z.union([z.literal(''), z.email()]),
	tls_25: z.enum(['none', 'may', 'encrypt']),
	tls_587: z.enum(['none', 'may', 'encrypt']),
	tenant_id: z.string().trim().max(128),
	client_id: z.string().trim().max(128),
	auto_refresh_minutes: z.coerce.number().int().min(0).max(1440)
});
export const relaySettingsSchema = z.object({
	csrf: z.string().min(1),
	hostname: z.string().trim().min(1).max(253),
	domain: z.string().trim().min(1).max(253),
	relayhost: z.string().trim().min(1).max(512)
});
export const networkSettingsSchema = z.object({
	csrf: z.string().min(1),
	mynetworks: z.string().trim().min(1),
	tls_25: z.enum(['none', 'may', 'encrypt']),
	tls_587: z.enum(['none', 'may', 'encrypt'])
});
export const microsoftSettingsSchema = z.object({
	csrf: z.string().min(1),
	ms365_smtp_user: z.email('Enter the licensed Microsoft 365 mailbox.'),
	tenant_id: z.string().trim().min(1).max(128),
	client_id: z.string().trim().min(1).max(128),
	auto_refresh_minutes: z.coerce.number().int().min(1).max(1440)
});
export const smtpClientSchema = z.object({
	csrf: z.string().min(1),
	login: username,
	password: strongPassword
});
export const senderSchema = z.object({
	csrf: z.string().min(1),
	login: username,
	address: z.email()
});
export const testMailSchema = z.object({
	csrf: z.string().min(1),
	to_addr: z.email(),
	from_addr: z.union([z.literal(''), z.email()]),
	subject: z.string().trim().min(1).max(200),
	body: z.string().max(10000)
});
