#!/usr/bin/env node

const { spawn } = require("node:child_process");
const path = require("node:path");
const { runCheck } = require("./check-environment");

// Valide la présence et la version de Node (>=16) et Python (>=3.10)
const pyCmd = runCheck();

const pyScript = path.join(__dirname, "..", "ai_secret_scout.py");

// Sans shell : les arguments sont transmis tels quels (espaces, guillemets), y compris sous Windows.
const child = spawn(pyCmd, [pyScript, ...process.argv.slice(2)], {
	stdio: "inherit",
	env: process.env,
});

child.on("error", (err) => {
	const isFr = (process.env.LANG || process.env.LC_ALL || "")
		.toLowerCase()
		.includes("fr");
	if (err.code === "ENOENT") {
		if (isFr) {
			console.error(
				"❌ Erreur : Python 3 (python3) est introuvable sur votre machine.",
			);
			console.error(
				"AI Secret Scout nécessite Python 3 (bibliothèque standard).",
			);
		} else {
			console.error(
				"❌ Error: Python 3 (python3) could not be found on your system.",
			);
			console.error(
				"AI Secret Scout requires Python 3.10+ (standard library).",
			);
		}
	} else {
		console.error(
			isFr
				? `❌ Erreur lors du lancement d'AI Secret Scout : ${err.message}`
				: `❌ Error launching AI Secret Scout: ${err.message}`,
		);
	}
	process.exit(1);
});

child.on("exit", (code) => {
	process.exit(code ?? 0);
});
