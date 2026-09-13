const { test } = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { PYTHON, SCRIPT, homeEnv, runPython, withHome } = require("./helpers");

const GITHUB_TOKEN = `ghp${"_"}R8mQz4LkW2vNc7HpX9sJ3bTf6YgK1aUe5DhZ`;
const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;?]*[a-zA-Z]`, "g");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("le caviardage préserve les octets non UTF-8 et les fins de ligne CRLF", () =>
	withHome({}, (home) => {
		const file = path.join(
			home,
			".claude",
			"projects",
			"-tmp-demo",
			"session.jsonl",
		);
		fs.mkdirSync(path.dirname(file), { recursive: true });
		const line = (value) =>
			Buffer.from(`{"type":"user","message":{"content":"${value}"}}\r\n`);
		const invalid = Buffer.from([0xff, 0xfe, 0x0a]);
		const original = Buffer.concat([line(GITHUB_TOKEN), invalid]);
		fs.writeFileSync(file, original);

		const result = runPython(
			home,
			[
				"import json; from pathlib import Path; import ai_secret_scout as a",
				"e = a.ScoutEngine(Path(sys.argv[1]))",
				'f = [x for x in e.scan() if x.category.startswith("GitHub")][0]',
				"print(json.dumps({'ok': e.redact_secret(f), 'backups': [str(b) for b in e.list_backups()]}))",
			].join("\n"),
		);

		assert.strictEqual(result.ok, true);
		assert.deepStrictEqual(
			fs.readFileSync(file),
			Buffer.concat([line("[REDACTED_BY_AISCOUT]"), invalid]),
		);
		assert.deepStrictEqual(fs.readFileSync(`${file}.bak`), original);
		assert.deepStrictEqual(result.backups, [`${file}.bak`]);
	}));

test("chaque libellé et chaque règle existent dans les deux langues", () =>
	withHome({}, (home) => {
		const result = runPython(
			home,
			[
				"import json; import ai_secret_scout as a",
				'fr, en = set(a.I18N_STRINGS["fr"]), set(a.I18N_STRINGS["en"])',
				'missing = [n for n in a.PATTERNS if n not in a.RULE_I18N["en"]]',
				"print(json.dumps({'only_fr': sorted(fr - en), 'only_en': sorted(en - fr), 'rules': missing}))",
			].join("\n"),
		);
		assert.deepStrictEqual(result, { only_fr: [], only_en: [], rules: [] });
	}));

test(
	"--watch signale un nouveau secret une seule fois, sans planter",
	{ timeout: 60000 },
	() =>
		withHome(
			{
				".claude/projects/-tmp-live/live.jsonl": [
					{ type: "user", message: { content: "init" } },
				],
			},
			async (home) => {
				const file = path.join(
					home,
					".claude",
					"projects",
					"-tmp-live",
					"live.jsonl",
				);
				const child = spawn(
					PYTHON,
					[SCRIPT, "--watch", "--lang", "en", "--home-dir", home],
					{
						env: homeEnv(home),
					},
				);
				let out = "";
				let err = "";
				child.stdout.on("data", (d) => {
					out += d;
				});
				child.stderr.on("data", (d) => {
					err += d;
				});
				const plain = () => out.replace(ANSI, "");
				const waitFor = async (pattern) => {
					const start = Date.now();
					while (!pattern.test(plain())) {
						assert.strictEqual(
							child.exitCode,
							null,
							`watchdog arrêté prématurément :\n${err}`,
						);
						assert.ok(
							Date.now() - start < 20000,
							`délai dépassé en attendant ${pattern}\n${err}`,
						);
						await sleep(100);
					}
				};

				try {
					await waitFor(/Sentinel started/);
					// Laisse passer la seconde : certains systèmes de fichiers arrondissent le mtime.
					await sleep(1100);
					fs.appendFileSync(
						file,
						`${JSON.stringify({ type: "user", message: { content: GITHUB_TOKEN } })}\n`,
					);
					await waitFor(/ALERT: GitHub Token/);

					// Nouvelle écriture dans la même session : le secret déjà signalé ne doit pas revenir.
					await sleep(1100);
					fs.appendFileSync(
						file,
						`${JSON.stringify({ type: "assistant", message: { content: "ok" } })}\n`,
					);
					await sleep(3000);

					const counters = [...plain().matchAll(/Alerts Triggered : (\d+)/g)];
					assert.strictEqual(counters.at(-1)[1], "1");
					assert.doesNotMatch(err, /Traceback/);
				} finally {
					if (child.exitCode === null) {
						const exited = new Promise((resolve) =>
							child.once("exit", resolve),
						);
						child.kill();
						await exited;
					}
				}
			},
		),
);
