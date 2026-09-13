const { test } = require("node:test");
const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runPython, withHome } = require("./helpers");

// Titre piégé : le nom d'un projet vient du dossier de la session, donc d'un dépôt cloné.
// Sans guillemets dans la charge, pour qu'elle reste valide quel que soit l'échappement tenté.
function trappedTitle(marker) {
	return `Secret — projet $(New-Item -ItemType File -Path ${marker})`;
}

function buildNotification(home, title, message) {
	return runPython(
		home,
		[
			"import json; import ai_secret_scout as a",
			`args, env = a.build_windows_notification(${JSON.stringify(title)}, ${JSON.stringify(message)})`,
			"print(json.dumps({'args': args, 'title': env['AISCOUT_BALLOON_TITLE'], 'text': env['AISCOUT_BALLOON_TEXT']}))",
		].join("\n"),
	);
}

test("notification Windows : le titre n'est jamais inséré dans la commande PowerShell", () =>
	withHome({}, (home) => {
		const title = trappedTitle(path.join(home, "pwned"));
		const notif = buildNotification(home, title, "ligne 1\nligne 2");
		assert.strictEqual(notif.args[0], "powershell");
		for (const arg of notif.args) {
			assert.ok(
				!arg.includes("New-Item"),
				`charge présente dans l'argument : ${arg}`,
			);
		}
		assert.strictEqual(notif.title, title);
		assert.strictEqual(notif.text, "ligne 1 ligne 2");
	}));

test(
	"notification Windows : PowerShell n'exécute pas un « $(...) » du nom de projet",
	{ skip: process.platform !== "win32" && "PowerShell Windows uniquement" },
	() =>
		withHome({}, (home) => {
			// Dossier sans espace : la charge n'a besoin d'aucun guillemet.
			const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aiscout-pwn-"));
			const marker = path.join(dir, "pwned");
			try {
				// Contrôle positif : insérée dans la chaîne comme avant la 2.4.8, la charge s'exécute.
				const legacy = spawnSync(
					"powershell",
					[
						"-NoProfile",
						"-NonInteractive",
						"-Command",
						`$t = "${trappedTitle(marker).replaceAll('"', '`"')}"`,
					],
					{ encoding: "utf-8", timeout: 60000 },
				);
				assert.strictEqual(legacy.error, undefined, String(legacy.error));
				assert.ok(
					fs.existsSync(marker),
					"le contrôle positif n'a pas reproduit l'injection",
				);
				fs.rmSync(marker);

				const notif = buildNotification(home, trappedTitle(marker), "texte");
				const result = spawnSync(notif.args[0], notif.args.slice(1), {
					encoding: "utf-8",
					timeout: 60000,
					env: {
						...process.env,
						AISCOUT_BALLOON_TITLE: notif.title,
						AISCOUT_BALLOON_TEXT: notif.text,
					},
				});
				assert.strictEqual(result.error, undefined, String(result.error));
				assert.ok(!fs.existsSync(marker), "la charge du titre a été exécutée");
			} finally {
				fs.rmSync(dir, { recursive: true, force: true });
			}
		}),
);
