const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { checkPythonVersion } = require("../bin/check-environment");

const ROOT = path.join(__dirname, "..");
const LAUNCHER = path.join(ROOT, "bin", "aiscout.js");
const SCRIPT = path.join(ROOT, "ai_secret_scout.py");
const PYTHON = checkPythonVersion().cmd;

const hasRipgrep = spawnSync("rg", ["--version"]).status === 0;

// Le moteur a deux chemins de scan : chaque test de détection tourne sur les deux.
const SCAN_MODES = [
	{ name: "repli Python", env: { AISCOUT_DISABLE_RIPGREP: "1" } },
	{ name: "ripgrep", env: {}, skip: hasRipgrep ? false : "ripgrep absent" },
];

// Faux $HOME : le scan ne lit jamais les vrais historiques, et rules.json est créé ici.
// `files` associe un chemin relatif à ses lignes (objet sérialisé en JSON, ou texte brut).
function makeHome(files) {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "aiscout-test-"));
	for (const [rel, lines] of Object.entries(files)) {
		const file = path.join(home, ...rel.split("/"));
		fs.mkdirSync(path.dirname(file), { recursive: true });
		const text = lines
			.map((l) => (typeof l === "string" ? l : JSON.stringify(l)))
			.join("\n");
		fs.writeFileSync(file, `${text}\n`);
	}
	return home;
}

async function withHome(files, fn) {
	const home = makeHome(files);
	try {
		return await fn(home);
	} finally {
		fs.rmSync(home, { recursive: true, force: true });
	}
}

function homeEnv(home, extra = {}) {
	return {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		APPDATA: home,
		AISCOUT_NO_NOTIFY: "1",
		...extra,
	};
}

function runScout(home, args, extraEnv = {}) {
	const result = spawnSync(
		process.execPath,
		[LAUNCHER, ...args, "--home-dir", home],
		{ encoding: "utf-8", env: homeEnv(home, extraEnv) },
	);
	assert.strictEqual(result.status, 0, result.stderr);
	return result.stdout;
}

// Exécute du Python avec le moteur importable (`import ai_secret_scout`).
function runPython(home, code) {
	const prelude = `import sys; sys.path.insert(0, ${JSON.stringify(ROOT)})\n`;
	const result = spawnSync(PYTHON, ["-c", prelude + code, home], {
		encoding: "utf-8",
		env: homeEnv(home),
	});
	assert.strictEqual(result.status, 0, result.stderr);
	return JSON.parse(result.stdout);
}

module.exports = {
	PYTHON,
	SCAN_MODES,
	SCRIPT,
	homeEnv,
	runPython,
	runScout,
	withHome,
};
