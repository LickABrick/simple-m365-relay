type UpdateStatus = {
	ok: boolean;
	currentVersion: string;
	latestVersion?: string;
	updateAvailable: boolean;
	url: string;
};

let cache: { expires: number; value: UpdateStatus } | undefined;
const semver = (value: string) => {
	const match = value.match(/v?(\d+)\.(\d+)\.(\d+)/);
	return match ? match.slice(1).map(Number) : null;
};

export async function getUpdateStatus(): Promise<UpdateStatus> {
	if (cache && cache.expires > Date.now()) return cache.value;
	const currentVersion = process.env.APP_VERSION || '2.0.0-rc.1';
	const repository = process.env.APP_GITHUB_REPO || 'LickABrick/simple-m365-relay';
	const url = `https://github.com/${repository}/releases/latest`;
	let value: UpdateStatus = { ok: false, currentVersion, updateAvailable: false, url };
	try {
		const response = await fetch(`https://api.github.com/repos/${repository}/releases/latest`, {
			headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'simple-m365-relay' },
			signal: AbortSignal.timeout(6000)
		});
		if (!response.ok) throw new Error(`GitHub returned ${response.status}`);
		const release = (await response.json()) as { tag_name?: string; html_url?: string };
		const current = semver(currentVersion),
			latest = semver(release.tag_name || '');
		value = {
			ok: true,
			currentVersion,
			latestVersion: release.tag_name,
			updateAvailable: Boolean(
				current &&
				latest &&
				latest.some((part, index) => part !== current[index]) &&
				latest.join('.').localeCompare(current.join('.'), undefined, { numeric: true }) > 0
			),
			url: release.html_url || url
		};
	} catch {
		/* update checks must never affect relay operation */
	}
	cache = { expires: Date.now() + 12 * 60 * 60 * 1000, value };
	return value;
}
