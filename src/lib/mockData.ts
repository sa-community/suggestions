import { table } from "$lib/server";
import { db } from "./server/db";
import type { Image, Suggestion } from "./server/db/schema";

function randomInt(min: number, max: number) {
	min = Math.ceil(min);
	max = Math.floor(max);
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

export async function mockSuggestion(userId: string): Promise<Suggestion> {
	const imageIds = (await db.select({ id: table.image.id }).from(table.image)).map(
		(image) => image.id,
	);

	const voterIds = (await db.select({ id: table.user.id }).from(table.user)).map((user) => user.id);

	function getRandomNItems<T>(arr: T[], n?: number): T[] {
		if (arr.length === 0) return [];

		const start = Math.floor(Math.random() * arr.length);
		const numberOfItems = n ?? arr.length - start;

		return arr.slice(start, start + numberOfItems);
	}
	return {
		id: crypto.randomUUID(),
		authorId: userId,
		title: `Suggestion ${(Math.random() * 10_000).toFixed(0)}`,
		description: `Description ${(Math.random() * 10_000).toFixed(0)}`,
		voterIds: getRandomNItems(voterIds as unknown as string[]),
		imageIds: getRandomNItems(imageIds),
		tag: (() => {
			const tag: Suggestion["tag"][] = ["website", "editor", "other", "everywhere"];
			return tag[randomInt(0, tag.length - 1)];
		})(),
		status: (() => {
			const statuses: Suggestion["status"][] = [
				"pending",
				"good",
				"implemented",
				"in-dev",
				"incompatible",
				"impractical",
				"rejected",
				"impossible",
			];
			return statuses[Math.floor(Math.random() * statuses.length)];
		})(),
		createdAt: new Date(Date.now()),
		visible: true,
	};
}

export async function mockImage(provider: "placehold" | "picsum" = "picsum"): Promise<Image> {
	const width = Math.floor(Math.random() * 500) + 300;
	const height = Math.floor(Math.random() * 500) + 300;
	const url =
		provider === "placehold"
			? `https://placehold.co/${width}x${height}`
			: `https://picsum.photos/seed/${(Math.random() * 10_000).toFixed(0)}/${width}/${height}`;

	return {
		id: crypto.randomUUID(),
		url,
		resolution: { x: width, y: height },
		cloudinaryId: null,
	};
}
