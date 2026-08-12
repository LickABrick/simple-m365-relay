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
