export type QueueEntry = {
	id: string;
	size: number;
	arrival: string;
	sender: string;
	recipients: string[];
	reason: string;
};

export function parseQueue(raw: string): QueueEntry[] {
	const entries: QueueEntry[] = [];
	let current: QueueEntry | undefined;
	for (const line of raw.split('\n')) {
		const start = line.match(/^([A-F0-9]+)[*!]?\s+(\d+)\s+(.{20})\s+(\S.*)$/);
		if (start) {
			current = {
				id: start[1],
				size: Number(start[2]),
				arrival: start[3].trim(),
				sender: start[4].trim(),
				recipients: [],
				reason: ''
			};
			entries.push(current);
			continue;
		}
		if (!current) continue;
		const value = line.trim();
		if (value.startsWith('(') && value.endsWith(')')) current.reason = value.slice(1, -1);
		else if (value && !value.startsWith('--')) current.recipients.push(value);
	}
	return entries;
}

export type LogEntry = {
	time: string;
	service: string;
	message: string;
	severity: 'error' | 'warning' | 'info';
};

export function parseLog(raw: string): LogEntry[] {
	return raw
		.split('\n')
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => {
			const match = line.match(/^(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+\S+\s+([^:]+):\s*(.*)$/);
			const message = match?.[3] || line;
			const severity = /(fatal|error|fail|reject|deferred|denied|535\s)/i.test(message)
				? 'error'
				: /warn/i.test(message)
					? 'warning'
					: 'info';
			return { time: match?.[1] || '', service: match?.[2] || 'postfix', message, severity };
		});
}

export type OperationalProblem = {
	source: 'queue' | 'log';
	severity: 'error' | 'warning';
	message: string;
	context: string;
};

export function summarizeOperationalProblems(queue: string, log: string): OperationalProblem[] {
	const queued = parseQueue(queue)
		.filter((entry) => entry.reason)
		.map((entry) => ({
			source: 'queue' as const,
			severity: 'error' as const,
			message: entry.reason,
			context: `Queue ${entry.id}`
		}));
	const logged = parseLog(log)
		.filter(
			(entry): entry is LogEntry & { severity: 'error' | 'warning' } => entry.severity !== 'info'
		)
		.slice(-5)
		.reverse()
		.map((entry) => ({
			source: 'log' as const,
			severity: entry.severity,
			message: entry.message,
			context: [entry.time, entry.service].filter(Boolean).join(' · ')
		}));
	return [...queued, ...logged].slice(0, 6);
}
