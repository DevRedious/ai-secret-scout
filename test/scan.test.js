const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { SCAN_MODES, runScout, withHome } = require("./helpers");

// Jetons assemblés à l'exécution : aucune valeur au format réel n'est écrite dans le dépôt.
const GITHUB_TOKEN = `ghp${"_"}R8mQz4LkW2vNc7HpX9sJ3bTf6YgK1aUe5DhZ`;
const PLACEHOLDER_TOKEN = `ghp${"_"}${"x".repeat(36)}`;
// Contient « dev » et « test » : un jeton aléatoire ne doit pas passer pour un exemple.
const GITHUB_TOKEN_WORDS = `ghp${"_"}devR8mQz4LkW2testNc7HpX9sJ3bTf6YgK1a`;
const ANTHROPIC_KEY = `sk-${"ant"}-api03-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0UvWxYz12`;
const DB_PASSWORD = "Zq8vLr2mXw";
const DB_URI = `postgres${"://"}bob:${DB_PASSWORD}@db.acme.io:5432/app`;
const PKCS8_HEADER = `-----BEGIN ${"PRIVATE"} KEY-----`;
const ENCRYPTED_HEADER = `-----BEGIN ENCRYPTED ${"PRIVATE"} KEY-----`;
const PROMPT_PASSWORD = "Kx9!mQ2#vL";

const SESSION = ".claude/projects/-tmp-demo/session.jsonl";

function scanJson(home, env, extraArgs = []) {
	return JSON.parse(runScout(home, ["--json", ...extraArgs], env));
}

for (const mode of SCAN_MODES) {
	const opts = { skip: mode.skip };

	test(
		`[${mode.name}] --json détecte un jeton GitHub et l'attribue au projet`,
		opts,
		() =>
			withHome(
				{
					[SESSION]: [
						{ type: "user", cwd: "/tmp/demo", message: { content: "init" } },
						{
							type: "user",
							message: { content: `mon token : ${GITHUB_TOKEN}` },
						},
						{
							type: "user",
							message: { content: `exemple : ${PLACEHOLDER_TOKEN}` },
						},
					],
				},
				(home) => {
					const findings = scanJson(home, mode.env);
					const github = findings.filter((f) =>
						f.category.startsWith("GitHub"),
					);
					assert.strictEqual(github.length, 1);
					assert.strictEqual(github[0].secret_raw, GITHUB_TOKEN);
					assert.strictEqual(github[0].tool, "Claude Code");
					assert.strictEqual(github[0].project, "/tmp/demo");
					assert.strictEqual(github[0].line_no, 2);
					assert.ok(!findings.some((f) => f.secret_raw === PLACEHOLDER_TOKEN));
				},
			),
	);

	test(
		`[${mode.name}] détecte URI Postgres, clés PKCS#8, mot de passe entre guillemets`,
		opts,
		() =>
			withHome(
				{
					[SESSION]: [
						{ type: "user", cwd: "/tmp/demo", message: { content: "init" } },
						{ type: "user", message: { content: DB_URI } },
						{
							type: "user",
							message: {
								content: `${PKCS8_HEADER}\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----`,
							},
						},
						{
							type: "user",
							message: {
								content: `${ENCRYPTED_HEADER}\nMIIFHDBOBgkqhk\n-----END ENCRYPTED PRIVATE KEY-----`,
							},
						},
						{
							type: "user",
							message: { content: `password="${PROMPT_PASSWORD}"` },
						},
					],
				},
				(home) => {
					const findings = scanJson(home, mode.env);
					const pick = (cat) =>
						findings
							.filter((f) => f.category_raw === cat)
							.map((f) => [f.secret_raw, f.line_no]);

					// Seul le mot de passe est retenu : le caviardage laisse l'URI lisible.
					assert.deepStrictEqual(
						pick("Base de données (URI avec mot de passe)"),
						[[DB_PASSWORD, 2]],
					);
					assert.deepStrictEqual(
						pick("Clé Privée (SSH / RSA / ECC)").sort((a, b) => a[1] - b[1]),
						[
							[PKCS8_HEADER, 3],
							[ENCRYPTED_HEADER, 4],
						],
					);
					assert.deepStrictEqual(pick("Mot de passe en clair dans le Prompt"), [
						[PROMPT_PASSWORD, 5],
					]);
					for (const f of findings) {
						assert.notStrictEqual(
							f.timestamp,
							"Inconnu",
							`date absente pour ${f.category_raw}`,
						);
					}
				},
			),
	);

	test(
		`[${mode.name}] une clé Anthropic n'est pas aussi comptée comme clé OpenAI`,
		opts,
		() =>
			withHome(
				{ [SESSION]: [{ type: "user", message: { content: ANTHROPIC_KEY } }] },
				(home) => {
					const findings = scanJson(home, mode.env);
					assert.deepStrictEqual(
						findings.map((f) => f.category_raw),
						["Anthropic API Key"],
					);
				},
			),
	);

	test(
		`[${mode.name}] un jeton contenant « dev » ou « test » reste détecté`,
		opts,
		() =>
			withHome(
				{
					[SESSION]: [
						{ type: "user", message: { content: GITHUB_TOKEN_WORDS } },
					],
				},
				(home) => {
					const findings = scanJson(home, mode.env);
					assert.ok(findings.some((f) => f.secret_raw === GITHUB_TOKEN_WORDS));
				},
			),
	);

	test(
		`[${mode.name}] un « : » dans le chemin ne fausse ni fichier ni ligne`,
		{
			skip:
				mode.skip ||
				(process.platform === "win32" && "« : » interdit dans un nom Windows"),
		},
		() =>
			withHome(
				{
					".claude/projects/-tmp-a:b/s.jsonl": [
						{ type: "user", message: { content: "init" } },
						{ type: "user", message: { content: GITHUB_TOKEN } },
					],
				},
				(home) => {
					const [finding] = scanJson(home, mode.env);
					assert.strictEqual(
						finding.file_path,
						path.join(home, ".claude", "projects", "-tmp-a:b", "s.jsonl"),
					);
					assert.strictEqual(finding.line_no, 2);
				},
			),
	);

	test(`[${mode.name}] scanne l'historique des prompts Codex`, opts, () =>
		withHome(
			{
				".codex/history.jsonl": [
					{ session_id: "019a", ts: 1757800000, text: "init" },
					{ session_id: "019a", ts: 1757800001, text: `clé : ${GITHUB_TOKEN}` },
				],
			},
			(home) => {
				const [finding] = scanJson(home, mode.env);
				assert.strictEqual(finding.secret_raw, GITHUB_TOKEN);
				assert.strictEqual(finding.tool, "Codex");
				assert.strictEqual(
					finding.file_path,
					path.join(home, ".codex", "history.jsonl"),
				);
				assert.strictEqual(finding.line_no, 2);
			},
		),
	);

	test(`[${mode.name}] attribue le contexte « prompt Antigravity »`, opts, () =>
		withHome(
			{
				".gemini/antigravity-cli/brain/abcd1234/steps.jsonl": [
					{
						step_index: 0,
						type: "USER_INPUT",
						content: `voici ${GITHUB_TOKEN}`,
					},
				],
			},
			(home) => {
				const [finding] = scanJson(home, mode.env, ["--lang", "en"]);
				assert.strictEqual(finding.usage_context, "Antigravity user prompt");
			},
		),
	);

	test(
		`[${mode.name}] règle personnalisée refusée par ripgrep, et regex invalide ignorée`,
		opts,
		() =>
			withHome(
				{
					[SESSION]: [
						{
							type: "user",
							message: { content: `a zzq7k2m9zzq7k2m9 b ${GITHUB_TOKEN}` },
						},
					],
				},
				(home) => {
					const rules = JSON.stringify({
						// Rétroréférence : syntaxe Python que ripgrep refuse.
						"Jeton Double": {
							regex: "\\b(zz[a-z0-9]{6})\\1\\b",
							severity: "MOYEN",
						},
						Cassee: { regex: "([a-z", severity: "MOYEN" },
					});
					// ~/.config/aiscout sous Linux/macOS, %APPDATA%\aiscout sous Windows.
					for (const dir of [
						path.join(home, ".config", "aiscout"),
						path.join(home, "aiscout"),
					]) {
						fs.mkdirSync(dir, { recursive: true });
						fs.writeFileSync(path.join(dir, "rules.json"), rules);
					}
					const findings = scanJson(home, mode.env);
					const custom = findings.filter(
						(f) => f.category_raw === "Jeton Double [CUSTOM]",
					);
					assert.deepStrictEqual(
						custom.map((f) => f.secret_raw),
						["zzq7k2m9"],
					);
					assert.ok(findings.some((f) => f.secret_raw === GITHUB_TOKEN));
				},
			),
	);
}

test("--restore retrouve la sauvegarde d'une cible fichier (history.jsonl)", () =>
	withHome(
		{
			".claude/history.jsonl": ["[REDACTED_BY_AISCOUT]"],
			".claude/history.jsonl.bak": ["original"],
		},
		(home) => {
			const out = runScout(home, ["--restore", "--lang", "en"]);
			assert.match(out, /1 file\(s\) successfully restored/);
			const history = path.join(home, ".claude", "history.jsonl");
			assert.strictEqual(fs.readFileSync(history, "utf-8"), "original\n");
			assert.ok(!fs.existsSync(`${history}.bak`));
		},
	));

test("--list-rules liste les règles intégrées", () =>
	withHome({ [SESSION]: ["{}"] }, (home) => {
		const out = runScout(home, ["--list-rules", "--lang", "en"]);
		assert.match(out, /GitHub Token/);
		assert.match(out, /Private Key/);
	}));
