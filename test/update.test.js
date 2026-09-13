const { test } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { homeEnv, withHome } = require("./helpers");

const ROOT = path.join(__dirname, "..");
const LAUNCHER = path.join(ROOT, "bin", "aiscout.js");
const { version } = require("../package.json");

// Faux npm : note ses appels dans un journal et répond aux seules questions posées par `update`.
// Aucun test ne touche au vrai registre.
function writeFakeNpm(dir) {
	if (process.platform === "win32") {
		const file = path.join(dir, "npm.cmd");
		fs.writeFileSync(
			file,
			[
				"@echo off",
				'echo %*>>"%FAKE_NPM_LOG%"',
				'if "%1"=="view" echo %FAKE_NPM_LATEST%',
				'if "%1"=="root" echo %FAKE_NPM_ROOT%',
				"",
			].join("\r\n"),
		);
		return file;
	}
	const file = path.join(dir, "npm");
	fs.writeFileSync(
		file,
		[
			"#!/bin/sh",
			'echo "$*" >> "$FAKE_NPM_LOG"',
			'case "$1" in',
			'  view) echo "$FAKE_NPM_LATEST" ;;',
			'  root) echo "$FAKE_NPM_ROOT" ;;',
			"esac",
			"",
		].join("\n"),
	);
	fs.chmodSync(file, 0o755);
	return file;
}

function runUpdate(home, { latest, npmRoot, npm }) {
	const log = path.join(home, "npm.log");
	fs.writeFileSync(log, "");
	const result = spawnSync(
		process.execPath,
		[LAUNCHER, "update", "--lang", "en"],
		{
			encoding: "utf-8",
			env: homeEnv(home, {
				AISCOUT_NPM: npm ?? writeFakeNpm(home),
				FAKE_NPM_LATEST: latest ?? "",
				FAKE_NPM_ROOT: npmRoot ?? home,
				FAKE_NPM_LOG: log,
			}),
		},
	);
	return { ...result, calls: fs.readFileSync(log, "utf-8") };
}

test("--version affiche la version de package.json", () =>
	withHome({}, (home) => {
		for (const flag of ["--version", "-V"]) {
			const result = spawnSync(process.execPath, [LAUNCHER, flag], {
				encoding: "utf-8",
				env: homeEnv(home),
			});
			assert.strictEqual(result.status, 0, result.stderr);
			assert.strictEqual(result.stdout.trim(), `aiscout ${version}`);
		}
	}));

test("update : rien à installer quand la version publiée n'est pas plus récente", () =>
	withHome({}, (home) => {
		const result = runUpdate(home, { latest: version });
		assert.strictEqual(result.status, 0, result.stderr);
		assert.match(result.stdout, /is up to date/);
		assert.doesNotMatch(result.calls, /install/);
	}));

test("update : hors installation globale npm, indique la commande sans rien écraser", () =>
	withHome({}, (home) => {
		const result = runUpdate(home, { latest: "999.0.0" });
		assert.strictEqual(result.status, 0, result.stderr);
		assert.match(result.stdout, /New version available: v.+ → v999\.0\.0/);
		assert.match(result.stdout, /npm install -g ai-secret-scout@latest/);
		assert.doesNotMatch(result.calls, /install/);
	}));

test(
	"update : installation globale npm, lance npm install -g",
	{
		skip:
			path.basename(ROOT) !== "ai-secret-scout" &&
			"le dépôt doit s'appeler ai-secret-scout pour simuler une installation globale",
	},
	() =>
		withHome({}, (home) => {
			// Le dossier parent du dépôt joue le rôle de `npm root -g`.
			const result = runUpdate(home, {
				latest: "999.0.0",
				npmRoot: path.dirname(ROOT),
			});
			assert.strictEqual(result.status, 0, result.stderr);
			assert.match(result.calls, /install -g ai-secret-scout@latest/);
			assert.match(result.stdout, /updated to v999\.0\.0/);
		}),
);

test("update : échoue proprement sans npm", () =>
	withHome({}, (home) => {
		const result = runUpdate(home, {
			npm: path.join(home, "absent", "npm"),
		});
		assert.strictEqual(result.status, 1);
		assert.match(result.stderr, /npm not found/);
	}));
