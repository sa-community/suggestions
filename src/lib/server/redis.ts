import { Redis } from "@upstash/redis";
import { REDIS_URL, REDIS_TOKEN } from "$env/static/private";

export const redis = new Redis({
	url: REDIS_URL,
	token: REDIS_TOKEN,
});

export const thing = 1_000;
