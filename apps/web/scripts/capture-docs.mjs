import { chromium } from '@playwright/test';

const baseURL = process.env.DOCS_BASE_URL || 'http://127.0.0.1:8000';
const username = process.env.DOCS_USERNAME;
const password = process.env.DOCS_PASSWORD;
const sessionCookie = process.env.DOCS_SESSION_COOKIE;
const output = new URL('../../../docs/screenshots/', import.meta.url).pathname;

if (!sessionCookie && (!username || !password)) {
	throw new Error(
		'Set DOCS_SESSION_COOKIE, or DOCS_USERNAME and DOCS_PASSWORD, for a configured instance.'
	);
}

const captures = [
	['/overview', '01-overview.jpg'],
	['/settings/relay#deployment-review', '02-deployment-review.jpg'],
	['/settings/network', '03-network-tls.jpg'],
	['/clients', '04-smtp-clients.jpg'],
	['/senders', '05-sender-policy.jpg'],
	['/microsoft', '06-microsoft-oauth.jpg'],
	['/activity', '07-live-activity.jpg'],
	['/recovery', '08-recovery.jpg']
];

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
	viewport: { width: 1440, height: 1000 },
	deviceScaleFactor: 1,
	colorScheme: 'dark'
});
const page = await context.newPage();

if (sessionCookie) {
	await context.addCookies([
		{
			name: 'sm365r_session_v2',
			value: sessionCookie,
			url: baseURL,
			httpOnly: true,
			sameSite: 'Strict'
		}
	]);
} else {
	await page.goto(`${baseURL}/login`);
	await page.getByLabel('Username').fill(username);
	await page.getByLabel('Password', { exact: true }).fill(password);
	if (new URL(page.url()).pathname === '/setup') {
		await page.getByLabel('Confirm password').fill(password);
		await page.getByRole('button', { name: 'Create administrator' }).click();
		await page.waitForURL((url) => url.pathname !== '/setup');
	} else {
		await page.getByRole('button', { name: 'Sign in' }).click();
		await page.waitForURL((url) => url.pathname !== '/login');
	}
}

const sanitize = async () => {
	await page.evaluate(() => {
		const replacements = [
			[/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, 'relay@example.invalid'],
			[
				/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
				'00000000-0000-4000-8000-000000000000'
			],
			[/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '192.0.2.10'],
			[/\b[A-Z0-9-]+\.(?:onmicrosoft\.com|mail\.protection\.outlook\.com)\b/gi, 'example.invalid'],
			[/\brelay\.[A-Z0-9.-]+\.local\b/gi, 'relay.example.internal'],
			[/\bproduction-test\.local\b/gi, 'example.internal'],
			[/(enter the code\s+)[A-Z0-9]+/gi, '$1[REDACTED]'],
			[/\brelay-admin\b/gi, 'operator']
		];
		const redact = (value) =>
			replacements.reduce(
				(next, [pattern, replacement]) => next.replace(pattern, replacement),
				value
			);
		const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
		let node;
		while ((node = walker.nextNode())) node.nodeValue = redact(node.nodeValue || '');
		for (const element of document.querySelectorAll('input, textarea')) {
			if ('value' in element) element.value = redact(element.value);
		}
		for (const alert of document.querySelectorAll('[data-slot="alert"]')) {
			if (/operational problems? detected/i.test(alert.textContent || '')) alert.remove();
		}
		for (const entry of document.querySelectorAll('.log-entry')) {
			if (/not owned by root|relay-diagnostic/i.test(entry.textContent || '')) entry.remove();
		}
	});
	const visible = await page.locator('body').innerText();
	if (/\b[A-Z0-9._%+-]+@(?!example\.invalid\b)[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(visible))
		throw new Error(`Sensitive email remained after sanitizing ${page.url()}`);
};

for (const [route, filename] of captures) {
	await page.goto(`${baseURL}${route}`);
	await page.waitForLoadState('domcontentloaded');
	await page.waitForTimeout(800);
	await sanitize();
	await page.screenshot({
		path: `${output}/${filename}`,
		type: 'jpeg',
		quality: 88,
		fullPage: true
	});
}

await browser.close();
