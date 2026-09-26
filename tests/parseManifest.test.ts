import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseManifest } from "../extensions/index.ts";

function tmpLock(name: string, contents: string): { dir: string; lock: string } {
	const dir = mkdtempSync(join(tmpdir(), "pi-deps-"));
	const lock = join(dir, name);
	writeFileSync(lock, contents);
	return { dir, lock };
}

describe("parseManifest — composer.lock", () => {
	it("reads packages and packages-dev as arrays of {name, version}", () => {
		const { dir, lock } = tmpLock(
			"composer.lock",
			JSON.stringify({
				packages: [
					{ name: "vendor/foo", version: "1.2.3" },
					{ name: "vendor/bar", version: "v2.0.0" },
				],
				"packages-dev": [{ name: "phpunit/phpunit", version: "10.5.0" }],
			}),
		);
		const pkgs = parseManifest("composer", lock, dir);
		assert.deepEqual(pkgs, [
			["vendor/foo", "1.2.3"],
			["vendor/bar", "v2.0.0"],
			["phpunit/phpunit", "10.5.0"],
		]);
	});

	it("does not produce numeric index names", () => {
		const { dir, lock } = tmpLock(
			"composer.lock",
			JSON.stringify({
				packages: [{ name: "vendor/foo", version: "1.2.3" }],
			}),
		);
		const pkgs = parseManifest("composer", lock, dir);
		assert.ok(pkgs.every(([n]) => !/^\d+$/.test(n)));
	});

	it("returns null when no package sections are arrays (fake-clean guard)", () => {
		const { dir, lock } = tmpLock(
			"composer.lock",
			JSON.stringify({ packages: { "a/b": "0.1.0" } }),
		);
		assert.equal(parseManifest("composer", lock, dir), null);
	});

	it("tolerates missing packages-dev", () => {
		const { dir, lock } = tmpLock(
			"composer.lock",
			JSON.stringify({ packages: [{ name: "a/b", version: "0.1.0" }] }),
		);
		assert.deepEqual(parseManifest("composer", lock, dir), [["a/b", "0.1.0"]]);
	});
});
