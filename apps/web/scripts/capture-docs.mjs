import { chromium } from '@playwright/test';

const baseURL = process.env.DOCS_BASE_URL || 'http://127.0.0.1:18002';
const output = new URL('../../../docs/screenshots/', import.meta.url).pathname;
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
	viewport: { width: 1440, height: 1000 },
	deviceScaleFactor: 1
});
const page = await context.newPage();

await page.goto(`${baseURL}/setup`);
await page.screenshot({ path: `${output}/01-setup-create-admin.jpg`, type: 'jpeg', quality: 88 });
await page.getByLabel('Username').fill('relay-admin');
await page.getByLabel('Password', { exact: true }).fill('RelayDemo!2026');
await page.getByLabel('Confirm password').fill('RelayDemo!2026');
await page.getByRole('button', { name: 'Create administrator' }).click();
await page.waitForURL(`${baseURL}/`);
await page.screenshot({ path: `${output}/02-dashboard-overview.jpg`, type: 'jpeg', quality: 88 });

for (const [anchor, filename] of [
	['configuration', '03-relay-configuration.jpg'],
	['clients', '04-smtp-clients.jpg'],
	['recovery', '05-backup-diagnostics.jpg']
]) {
	await page.locator(`#${anchor}`).scrollIntoViewIfNeeded();
	await page.screenshot({ path: `${output}/${filename}`, type: 'jpeg', quality: 88 });
}

await browser.close();
