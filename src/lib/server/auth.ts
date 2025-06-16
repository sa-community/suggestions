// src/lib/server/auth.ts
import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase64url, encodeHexLowerCase } from "@oslojs/encoding";
import { redis } from "$lib/server/redis";
import type { RequestEvent } from "@sveltejs/kit";
import { GitHub } from "arctic";
import { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, OAUTH_CALLBACK_URL } from "$env/static/private";
import { DAY_IN_MS } from "$lib";

export type SessionValidationResult = Awaited<ReturnType<typeof validateSessionToken>>;

export const sessionCookieName = "auth-session";

export function generateSessionToken() {
	const bytes = crypto.getRandomValues(new Uint8Array(18));
	return encodeBase64url(bytes);
}

export async function createSession(
	token: string,
	user: { id: string; username: string; displayName: string },
) {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const expiresAt = Date.now() + DAY_IN_MS * 30;

	await redis.set(
		sessionId,
		JSON.stringify({
			userId: user.id,
			username: user.username,
			displayName: user.displayName,
			expiresAt,
		}),
		{ px: DAY_IN_MS * 30 },
	);

	return { id: sessionId, userId: user.id, expiresAt: new Date(expiresAt) };
}

export async function validateSessionToken(token: string) {
	const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
	const sessionData: string | null = JSON.stringify(await redis.get(sessionId));

	if (!sessionData) {
		return { session: null, user: null };
	}

	const { userId, username, displayName, expiresAt } = JSON.parse(sessionData);
	if (Date.now() >= expiresAt) {
		await redis.del(sessionId);
		return { session: null, user: null };
	}

	const renewSession = Date.now() >= expiresAt - DAY_IN_MS * 15;
	if (renewSession) {
		const newExpiresAt = Date.now() + DAY_IN_MS * 30;
		await redis.set(
			sessionId,
			JSON.stringify({ userId, username, displayName, expiresAt: newExpiresAt }),
			{ px: DAY_IN_MS * 30 },
		);
	}

	return {
		session: { id: sessionId, userId, expiresAt: new Date(expiresAt) },
		user: { id: userId, username, displayName },
	};
}

export async function invalidateSession(sessionId: string) {
	await redis.del(sessionId);
}

export function setSessionTokenCookie(event: RequestEvent, token: string, expiresAt: Date) {
	event.cookies.set(sessionCookieName, token, {
		expires: expiresAt,
		path: "/",
	});
}

export function deleteSessionTokenCookie(event: RequestEvent) {
	event.cookies.delete(sessionCookieName, { path: "/" });
}

export const github = new GitHub(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, OAUTH_CALLBACK_URL);
