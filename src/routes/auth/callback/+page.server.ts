// src/routes/auth/callback/+page.server.ts
import { redirect } from "@sveltejs/kit";
import type { PageServerLoad } from "./$types";
import { github } from "$lib/server/auth";
import * as auth from "$lib/server/auth";
import { db } from "$lib/server/db";
import * as table from "$lib/server/db/schema";
import { eq } from "drizzle-orm";
import { OAUTH_CALLBACK_URL } from "$env/static/private";
import { DAY_IN_MS } from "$lib";

function extractErrorInfo(err: unknown): Record<string, unknown> {
	if (err instanceof Error) {
		const plainError = {
			name: err.name,
			message: err.message,
			stack: err.stack,
			...Object.fromEntries(
				Object.getOwnPropertyNames(err)
					.filter((k) => !["name", "message", "stack"].includes(k))
					// eslint-disable-next-line @typescript-eslint/no-explicit-any
					.map((k) => [k, (err as any)[k]]),
			),
		};
		return plainError;
	}
	if (typeof err === "object" && err !== null) {
		return Object.fromEntries(Object.entries(err).map(([k, v]) => [k, String(v)]));
	}
	return { value: String(err) };
}

export const load: PageServerLoad = async (event) => {
	const { url } = event;

	const searchParams = new URLSearchParams(url.search);
	const code = searchParams.get("code");
	const state = searchParams.get("state");
	const privateCode = searchParams.get("privateCode");

	const oauthProvider = privateCode ? "scratch" : "github";

	let oauthId;
	let username;
	let displayName;

	if (oauthProvider === "github") {
		try {
			if (!code || !state) {
				redirect(307, "/auth/error");
			}

			const tokens = await github.validateAuthorizationCode(code);
			const accessToken = tokens.accessToken();

			const response = await fetch("https://api.github.com/user", {
				headers: {
					Authorization: `Bearer ${accessToken}`,
					"User-Agent": "sa-suggestions",
				},
			});

			if (!response.ok) {
				const text = await response.text();
				throw new Error(`GitHub API error ${response.status}: ${text}`);
			}

			const githubUser = await response.json();

			if (!githubUser) redirect(307, "/auth/error");

			oauthId = githubUser.id;
			username = githubUser.login;
			displayName = githubUser.name;
		} catch (error) {
			const info = extractErrorInfo(error);

			console.error(info);
			redirect(307, "/auth/error?" + encodeURIComponent(JSON.stringify(info)));
		}
	}

	if (oauthProvider === "scratch") {
		await fetch(`https://auth.itinerary.eu.org/api/auth/verifyToken?privateCode=${privateCode}`, {
			method: "GET",
		})
			.then((response) => response.json())
			.then((data) => {
				if (data.valid === true && data.redirect === OAUTH_CALLBACK_URL) {
					oauthId = data.username;
					username = data.username;
					displayName = "";
				} else {
					redirect(307, "/auth/error");
				}
			});
	}

	let [dbUser] = await db.select().from(table.user).where(eq(table.user.oauthId, oauthId));

	if (!dbUser) {
		await db.insert(table.user).values({
			id: crypto.randomUUID(),
			oauthId,
			username,
			displayName,
			oauthProvider,
		});
	}

	[dbUser] = await db.select().from(table.user).where(eq(table.user.oauthId, oauthId));

	const sessionToken = auth.generateSessionToken();
	await auth.createSession(sessionToken, {
		id: dbUser.id,
		username: dbUser.username,
		displayName: dbUser.displayName || "",
	});

	auth.setSessionTokenCookie(event, sessionToken, new Date(Date.now() + 30 * DAY_IN_MS));

	redirect(302, "/account");
};
