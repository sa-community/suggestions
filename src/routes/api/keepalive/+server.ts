import { redis } from "$lib/server/redis";
import type { RequestHandler } from "@sveltejs/kit";

export const GET: RequestHandler = async ({ request }) => {
	if (request.headers.get("Authorization") !== `Bearer ${process.env.CRON_SECRET}`) {
		return new Response("Unauthorized", { status: 401 });
	}

	await redis.set("keepalive", Date.now(), { ex: 60 });
	return new Response("ok", { status: 200 });
};
