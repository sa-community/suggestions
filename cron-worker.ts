interface Env {
	CRON_SECRET: string;
	SITE_URL: string;
}

export default {
	async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext) {
		const response = await fetch(`${env.SITE_URL}/api/keepalive`, {
			headers: {
				Authorization: `Bearer ${env.CRON_SECRET}`,
			},
		});

		const text = await response.text();
		if (!response.ok) {
			throw new Error(`Keepalive failed: ${response.status} ${text}`);
		}
		console.log(`Keepalive OK (${response.status}): ${text}`);
	},
};
