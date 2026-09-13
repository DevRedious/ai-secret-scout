const { test } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const LAUNCHER = path.join(__dirname, "..", "bin", "aiscout.js");

// Jetons assemblés à l'exécution : aucune valeur au format réel n'est écrite dans le dépôt.
const GITHUB_TOKEN = `ghp${"_"}R8mQz4LkW2vNc7HpX9sJ3bTf6YgK1aUe5DhZ`;
const PLACEHOLDER_TOKEN = `ghp${"_"}${"x".repeat(36)}`;

// Faux $HOME : le scan ne lit jamais les vrais historiques, et rules.json est créé ici.
function makeFakeHome() {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "aiscout-test-"));
	const session = path.join(home, ".claude", "projects", "-tmp-demo");
	fs.mkdirSync(session, { recursive: true });
	const lines = [
		{ type: "user", cwd: "/tmp/demo", message: { content: "init" } },
		{ type: "user", message: { content: `mon token : ${GITHUB_TOKEN}` } },
		{ type: "user", message: { content: `exemple : ${PLACEHOLDER_TOKEN}` } },
	];
	fs.writeFileSync(
		path.join(session, "session.jsonl"),
		`${lines.map((l) => JSON.stringify(l)).join("\n")}\n`,
	);
	return home;
}

function runScout(home, args) {
	const result = spawnSync(
		process.execPath,
		[LAUNCHER, ...args, "--home-dir", home],
		{
			encoding: "utf-8",
			env: { ...process.env, HOME: home, USERPROFILE: home, APPDATA: home },
		},
	);
	assert.strictEqual(result.status, 0, result.stderr);
	return result.stdout;
}

test("--json détecte un jeton GitHub et l'attribue au projet", () => {
	const home = makeFakeHome();
	try {
		const findings = JSON.parse(runScout(home, ["--json"]));
		const github = findings.filter((f) => f.category.startsWith("GitHub"));
		assert.strictEqual(github.length, 1);
		assert.strictEqual(github[0].secret_raw, GITHUB_TOKEN);
		assert.strictEqual(github[0].tool, "Claude Code");
		assert.strictEqual(github[0].project, "/tmp/demo");
	} finally {
		fs.rmSync(home, { recursive: true, force: true });
	}
});

test("--json ignore les valeurs d'exemple", () => {
	const home = makeFakeHome();
	try {
		const findings = JSON.parse(runScout(home, ["--json"]));
		assert.ok(!findings.some((f) => f.secret_raw === PLACEHOLDER_TOKEN));
	} finally {
		fs.rmSync(home, { recursive: true, force: true });
	}
});

test("--list-rules liste les règles intégrées", () => {
	const home = makeFakeHome();
	try {
		const out = runScout(home, ["--list-rules", "--lang", "en"]);
		assert.match(out, /GitHub Token/);
		assert.match(out, /Private Key/);
	} finally {
		fs.rmSync(home, { recursive: true, force: true });
	}
});
