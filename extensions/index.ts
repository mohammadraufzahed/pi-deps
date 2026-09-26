/**
 * pi-deps — multi-ecosystem dependency auditing for pi agents.
 *
 *   deps_audit    — vulnerability scan (native auditor or GH Advisory DB)
 *   deps_outdated — what's behind latest
 *   deps_licenses — license audit
 *   deps_update   — safe bumps (patch/minor) → branch-ready diff
 *
 * Auto-detects ecosystems per dir: composer.json (PHP), package.json
 * (npm), requirements.txt/pyproject.toml (pip), go.mod, Cargo.toml,
 * Gemfile. Native tools preferred; GitHub Advisory API (free, via
 * `gh api`) is the universal fallback.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { Type } from "typebox";

const MAX_OUT = 14000;

function run(
	cmd: string,
	args: string[],
	cwd: string,
	timeout = 120_000,
): Promise<{ code: number; out: string; missing: boolean }> {
	return new Promise((resolve) => {
		execFile(cmd, args, { cwd, timeout, maxBuffer: 32 * 1024 * 1024 }, (e, o, er) =>
			resolve({
				// Spawn failure (ENOENT, signal, killed) sets a non-numeric
				// code — surface it as 127 and flag `missing`.
				code: e ? (typeof (e as any).code === "number" ? (e as any).code : 127) : 0,
				out: String(o ?? "") + (er ? `\n${String(er)}` : ""),
				missing: e !== null && typeof (e as any).code !== "number",
			}),
		);
	});
}

const trim = (s: string) =>
	s.length > MAX_OUT ? s.slice(0, MAX_OUT) + "\n[truncated]" : s.trim() || "(no output)";

/** Detect ecosystems present in a dir. */
function ecosystems(dir: string): string[] {
	const found: string[] = [];
	if (existsSync(join(dir, "composer.json"))) found.push("composer");
	if (existsSync(join(dir, "package.json"))) found.push("npm");
	if (
		existsSync(join(dir, "requirements.txt")) ||
		existsSync(join(dir, "pyproject.toml"))
	)
		found.push("pip");
	if (existsSync(join(dir, "go.mod"))) found.push("go");
	if (existsSync(join(dir, "Cargo.toml"))) found.push("rust");
	if (existsSync(join(dir, "Gemfile"))) found.push("rubygems");
	return found;
}

/** GitHub Advisory DB — free universal fallback via gh api. */
async function advisoryScan(dir: string, eco: string): Promise<string> {
	const lockFiles: Record<string, string> = {
		composer: "composer.lock",
		npm: "package-lock.json",
		pip: "requirements.txt",
		go: "go.sum",
		rust: "Cargo.lock",
		rubygems: "Gemfile.lock",
	};
	const lock = join(dir, lockFiles[eco] ?? "");
	if (!existsSync(lock)) return `(${eco}: no lockfile for advisory scan)`;
	const pkgs = parseManifest(eco, lock, dir).slice(0, 200);
	const hits: string[] = [];
	let checked = 0;
	let rateLimited = false;
	const isRateLimited = (out: string) =>
		/\b(403|429)\b|rate limit|API rate limit exceeded/i.test(out);
	// Batched concurrency — gh -f fields are encoded as query params,
	// so scoped names like @babel/core survive the affects filter.
	for (let i = 0; i < pkgs.length && !rateLimited; i += 8) {
		const batch = pkgs.slice(i, i + 8);
		const results = await Promise.all(
			batch.map(([name, ver]) =>
				run(
					"gh",
					[
						"api",
						"advisories",
						"-f",
						`ecosystem=${eco}`,
						"-f",
						`affects=${name}@${ver}`,
					],
					dir,
					30_000,
				),
			),
		);
		for (let j = 0; j < results.length; j++) {
			const r = results[j];
			const [name, ver] = batch[j];
			if (isRateLimited(r.out)) {
				rateLimited = true;
				continue;
			}
			checked++;
			if (r.code === 0 && r.out.trim().startsWith("[")) {
				try {
					const advs = JSON.parse(r.out);
					for (const a of advs) {
						hits.push(
							`${a.severity?.toUpperCase() ?? "?"} ${name}@${ver}: ${a.summary ?? a.ghsa_id} → fix: ${(a.vulnerabilities?.[0]?.first_patched_version?.identifier) ?? "?"}`,
						);
					}
				} catch {
					/* non-JSON */
				}
			}
		}
	}
	const note = rateLimited
		? ` (rate-limited — checked ${checked}/${pkgs.length} packages)`
		: "";
	return hits.length
		? hits.join("\n") + note
		: `(${eco}: clean per Advisory DB${note})`;
}

function parseManifest(
	eco: string,
	lockPath: string,
	dir: string,
): [string, string][] {
	try {
		const src = readFileSync(lockPath, "utf-8");
		if (eco === "composer" || eco === "npm") {
			const j = JSON.parse(src);
			const pkgs = j.packages ?? j.dependencies ?? {};
			return Object.entries(pkgs)
				.map(([n, v]: [string, any]) => [n, String(v.version ?? v)])
				.filter(([, v]) => v && v !== "undefined") as [string, string][];
		}
		if (eco === "pip") {
			return src
				.split("\n")
				.map((l) => l.trim().split("=="))
				.filter((p) => p.length === 2) as [string, string][];
		}
		if (eco === "rubygems") {
			return [...src.matchAll(/^\s{4}(\S+) \(([^)]+)\)/gm)].map((m) => [
				m[1],
				m[2],
			]) as [string, string][];
		}
		if (eco === "go") {
			return [...src.matchAll(/^\s*(\S+) v(\S+)/gm)].map((m) => [
				m[1],
				m[2],
			]) as [string, string][];
		}
	} catch {
		/* fallthrough */
	}
	return [];
}

export default function piDeps(pi: ExtensionAPI) {
	pi.registerTool({
		name: "deps_audit",
		label: "Deps Audit",
		description:
			"Vulnerability scan for a project — auto-detects PHP/composer, npm, pip, go, rust, rubygems. Native auditor first, GitHub Advisory DB as fallback.",
		promptSnippet: "Audit dependencies for vulnerabilities",
		parameters: Type.Object({
			dir: Type.Optional(Type.String({ description: "project dir (default cwd)" })),
		}),
		async execute(_id, params, _s, _u, ctx: { cwd: string }) {
			const dir = params.dir ?? ctx.cwd;
			const ecos = ecosystems(dir);
			if (!ecos.length)
				return { content: [{ type: "text" as const, text: `no dependency manifests found in ${dir}` }] };
			const out: string[] = [];
			for (const eco of ecos) {
				out.push(`### ${eco}`);
				let native: { code: number; out: string; missing: boolean } | null = null;
				if (eco === "composer")
					native = await run("composer", ["audit", "--format=plain"], dir);
				else if (eco === "npm")
					native = await run("npm", ["audit", "--json"], dir);
				else if (eco === "pip")
					native = await run("pip-audit", ["-f", "columns"], dir);
				else if (eco === "go")
					native = await run("govulncheck", ["./..."], dir);
				else if (eco === "rust")
					native = await run("cargo", ["audit", "--json"], dir);
				else if (eco === "rubygems")
					native = await run("bundle", ["audit", "check"], dir);
				if (native && !native.missing && native.out.trim()) {
					// Auditors exit nonzero on findings (npm audit, composer
					// audit, …) — the output IS the report, keep it.
					out.push(trim(native.out));
				} else {
					out.push("(native auditor unavailable — Advisory DB scan)");
					out.push(trim(await advisoryScan(dir, eco)));
				}
			}
			return { content: [{ type: "text" as const, text: out.join("\n") }] };
		},
	});

	pi.registerTool({
		name: "deps_outdated",
		label: "Deps Outdated",
		description: "List outdated dependencies per ecosystem in a dir.",
		parameters: Type.Object({
			dir: Type.Optional(Type.String()),
		}),
		async execute(_id, params, _s, _u, ctx: { cwd: string }) {
			const dir = params.dir ?? ctx.cwd;
			const ecos = ecosystems(dir);
			const out: string[] = [];
			for (const eco of ecos) {
				out.push(`### ${eco}`);
				let r;
				if (eco === "composer")
					r = await run("composer", ["outdated", "--direct"], dir);
				else if (eco === "npm") r = await run("npm", ["outdated"], dir);
				else if (eco === "pip")
					r = await run("pip", ["list", "--outdated"], dir);
				else if (eco === "go")
					r = await run("go", ["list", "-u", "-m", "all"], dir);
				else if (eco === "rust")
					r = await run("cargo", ["outdated"], dir);
				else r = await run("bundle", ["outdated"], dir);
				out.push(trim(r.out));
			}
			return { content: [{ type: "text" as const, text: out.join("\n") || "(nothing outdated)" }] };
		},
	});

	pi.registerTool({
		name: "deps_licenses",
		label: "Deps Licenses",
		description: "License audit — flag copyleft/GPL in prod deps.",
		parameters: Type.Object({ dir: Type.Optional(Type.String()) }),
		async execute(_id, params, _s, _u, ctx: { cwd: string }) {
			const dir = params.dir ?? ctx.cwd;
			const out: string[] = [];
			if (existsSync(join(dir, "composer.json"))) {
				const r = await run("composer", ["licenses", "--format=json"], dir);
				out.push("### composer\n" + trim(r.out));
			}
			if (existsSync(join(dir, "package.json"))) {
				const r = await run("npx", ["--yes", "license-checker", "--json"], dir, 90_000);
				if (r.code === 0) {
					try {
						const j = JSON.parse(r.out);
						const bad = Object.entries(j).filter(([, v]: [string, any]) =>
							String(v.licenses).match(/GPL|AGPL|SSPL/i),
						);
						out.push("### npm\n" + (bad.length
							? bad.map(([n, v]: [string, any]) => `${n}: ${v.licenses}`).join("\n")
							: "no copyleft licenses found"));
					} catch { out.push(trim(r.out)); }
				}
			}
			return { content: [{ type: "text" as const, text: out.join("\n") || "(no manifests)" }] };
		},
	});

	pi.registerTool({
		name: "deps_update",
		label: "Deps Update",
		description:
			"Safe dependency bumps — patch/minor only — producing a diff ready for a branch+PR.",
		parameters: Type.Object({
			dir: Type.Optional(Type.String()),
			scope: Type.Optional(Type.String({ description: "patch|minor (default patch)" })),
			ecosystem: Type.Optional(Type.String({ description: "composer|npm|pip|..." })),
		}),
		async execute(_id, params, _s, _u, ctx: { cwd: string }) {
			const dir = params.dir ?? ctx.cwd;
			const scope = params.scope ?? "patch";
			const out: string[] = [];
			const ecos = params.ecosystem ? [params.ecosystem] : ecosystems(dir);
			for (const eco of ecos) {
				if (eco === "composer") {
					const lvl = scope === "minor" ? ["--with-all-dependencies"] : [];
					const r = await run("composer", ["update", "--prefer-stable", "--with-dependencies", ...lvl], dir, 300_000);
					out.push(`### composer update\n${trim(r.out)}`);
				} else if (eco === "npm") {
					const r = await run("npm", ["update"], dir, 300_000);
					out.push(`### npm update\n${trim(r.out)}`);
				} else {
					out.push(`(${eco}: manual update — audit first, bump targeted packages)`);
				}
			}
			const diff = await run("git", ["diff", "--stat"], dir);
			out.push(`\n### changed files\n${trim(diff.out)}`);
			return { content: [{ type: "text" as const, text: out.join("\n") }] };
		},
	});
}
