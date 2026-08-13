type UpdateStatus = {
	ok: boolean;
	currentVersion: string;
	latestVersion?: string;
	updateAvailable: boolean;
	url: string;
};

let cache: { expires: number; etag?: string; value: UpdateStatus } | undefined;
type Semver = { core: [number, number, number]; prerelease: (string | number)[] };
const semver = (value: string): Semver | null => {
	const match = value
		.trim()
		.match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
	if (!match) return null;
	return {
		core: [Number(match[1]), Number(match[2]), Number(match[3])],
		prerelease: match[4]?.split('.').map((part) => (/^\d+$/.test(part) ? Number(part) : part)) || []
	};
};

export const compareVersions = (leftValue: string, rightValue: string): number => {
	const left = semver(leftValue),
		right = semver(rightValue);
	if (!left || !right) return 0;
	for (let index = 0; index < 3; index += 1) {
		if (left.core[index] !== right.core[index])
			return left.core[index] > right.core[index] ? 1 : -1;
	}
	if (!left.prerelease.length || !right.prerelease.length)
		return left.prerelease.length === right.prerelease.length ? 0 : left.prerelease.length ? -1 : 1;
	for (
		let index = 0;
		index < Math.max(left.prerelease.length, right.prerelease.length);
		index += 1
	) {
		const a = left.prerelease[index],
			b = right.prerelease[index];
		if (a === undefined || b === undefined) return a === undefined ? -1 : 1;
		if (a === b) continue;
		if (typeof a === 'number' && typeof b === 'string') return -1;
		if (typeof a === 'string' && typeof b === 'number') return 1;
		return a > b ? 1 : -1;
	}
	return 0;
};

export async function getUpdateStatus(): Promise<UpdateStatus> {
	if (cache && cache.expires > Date.now()) return cache.value;
	const currentVersion = process.env.APP_VERSION || '2.0.0-rc.2';
	const repository = process.env.APP_GITHUB_REPO || 'LickABrick/simple-m365-relay';
	const url = `https://github.com/${repository}/releases/latest`;
	let value: UpdateStatus = cache?.value || {
		ok: false,
		currentVersion,
		updateAvailable: false,
		url
	};
	try {
		const headers: Record<string, string> = {
			Accept: 'application/vnd.github+json',
			'User-Agent': 'simple-m365-relay',
			'X-GitHub-Api-Version': '2022-11-28'
		};
		if (cache?.etag) headers['If-None-Match'] = cache.etag;
		const response = await fetch(`https://api.github.com/repos/${repository}/releases/latest`, {
			headers,
			signal: AbortSignal.timeout(6000)
		});
		if (response.status === 304 && cache) {
			cache.expires = Date.now() + 12 * 60 * 60 * 1000;
			return cache.value;
		}
		if (!response.ok) throw new Error(`GitHub returned ${response.status}`);
		const release = (await response.json()) as { tag_name?: string; html_url?: string };
		const current = semver(currentVersion),
			latest = semver(release.tag_name || '');
		value = {
			ok: true,
			currentVersion,
			latestVersion: release.tag_name,
			updateAvailable: Boolean(
				current && latest && compareVersions(release.tag_name || '', currentVersion) > 0
			),
			url: release.html_url || url
		};
		cache = {
			expires: Date.now() + 12 * 60 * 60 * 1000,
			etag: response.headers.get('etag') || undefined,
			value
		};
		return value;
	} catch {
		/* update checks must never affect relay operation */
	}
	cache = { expires: Date.now() + 30 * 60 * 1000, etag: cache?.etag, value };
	return value;
}
