#!/usr/bin/env node

const { execSync } = require("node:child_process");
const fs = require("node:fs");

function isFrenchLocale() {
	const envLang = (
		process.env.LANG ||
		process.env.LC_ALL ||
		process.env.LC_MESSAGES ||
		""
	).toLowerCase();
	return envLang.includes("fr");
}

function checkNodeVersion() {
	const nodeVer = process.version;
	const major = parseInt(process.versions.node.split(".")[0], 10);
	return {
		ok: major >= 16,
		version: nodeVer,
		major,
	};
}

function checkPythonVersion() {
	const candidates =
		process.platform === "win32"
			? ["python", "py", "python3"]
			: ["python3", "python"];

	for (const cmd of candidates) {
		try {
			const output = execSync(
				`${cmd} -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"`,
				{
					encoding: "utf-8",
					stdio: ["pipe", "pipe", "ignore"],
					timeout: 3000,
				},
			).trim();

			const parts = output.split(".").map((n) => parseInt(n, 10));
			const major = parts[0];
			const minor = parts[1];

			if (major === 3 && minor >= 10) {
				return {
					ok: true,
					cmd,
					version: output,
					tooOld: false,
				};
			} else if (major === 3 || major === 2) {
				return {
					ok: false,
					cmd,
					version: output,
					tooOld: true,
				};
			}
		} catch {
			// Ignore and try next candidate
		}
	}

	return {
		ok: false,
		cmd: null,
		version: null,
		tooOld: false,
	};
}

function getInstallSuggestion(isFr) {
	if (process.platform === "win32") {
		if (isFr) {
			return "👉 Sous Windows, vous pouvez installer Python 3.10+ avec winget ou depuis le site officiel :\n     winget install Python.Python.3.12\n     ou téléchargez l'installeur : https://www.python.org/downloads/";
		}
		return "👉 On Windows, you can install Python 3.10+ via winget or from the official website:\n     winget install Python.Python.3.12\n     or download the installer from: https://www.python.org/downloads/";
	}

	let pkgManager = "apt";
	try {
		if (fs.existsSync("/etc/os-release")) {
			const osRelease = fs.readFileSync("/etc/os-release", "utf-8");
			if (/ID(_LIKE)?=.*(fedora|rhel|centos|nobara)/i.test(osRelease)) {
				pkgManager = "dnf";
			} else if (/ID(_LIKE)?=.*(arch|manjaro)/i.test(osRelease)) {
				pkgManager = "pacman";
			} else if (/ID(_LIKE)?=.*(suse)/i.test(osRelease)) {
				pkgManager = "zypper";
			} else if (/ID(_LIKE)?=.*(alpine)/i.test(osRelease)) {
				pkgManager = "apk";
			}
		}
	} catch {
		// Standard fallback
	}

	const commands = {
		dnf: "sudo dnf install -y python3",
		apt: "sudo apt update && sudo apt install -y python3",
		pacman: "sudo pacman -S python",
		zypper: "sudo zypper install python3",
		apk: "apk add python3",
	};

	const cmd = commands[pkgManager] || "sudo apt install python3";

	if (isFr) {
		return `👉 Commande d'installation recommandée pour votre distribution :\n     ${cmd}`;
	}
	return `👉 Recommended installation command for your distribution:\n     ${cmd}`;
}

function runCheck() {
	const isFr = isFrenchLocale();
	const nodeStatus = checkNodeVersion();
	const pyStatus = checkPythonVersion();

	if (!nodeStatus.ok) {
		console.error(
			isFr
				? `❌ Erreur : Version de Node.js obsolète (${nodeStatus.version}). Node.js >= 16.0.0 est requis.`
				: `❌ Error: Outdated Node.js version (${nodeStatus.version}). Node.js >= 16.0.0 is required.`,
		);
		process.exit(1);
	}

	if (!pyStatus.ok) {
		console.error(
			"\x1b[31m──────────────────────────────────────────────────────────────────\x1b[0m",
		);
		if (pyStatus.tooOld) {
			console.error(
				isFr
					? `❌ Version de Python trop ancienne : ${pyStatus.version} détecté (${pyStatus.cmd}).\n   AI Secret Scout requiert Python 3.10 ou supérieur.`
					: `❌ Python version too old: ${pyStatus.version} detected (${pyStatus.cmd}).\n   AI Secret Scout requires Python 3.10 or higher.`,
			);
		} else {
			console.error(
				isFr
					? "❌ Python 3 (python3) est introuvable sur votre système."
					: "❌ Python 3 (python3) could not be found on your system.",
			);
		}
		console.error("");
		console.error(getInstallSuggestion(isFr));
		console.error(
			isFr
				? "💡 Note : Aucun paquet pip externe n'est requis (seule la bibliothèque standard Python est utilisée)."
				: "💡 Note: No pip packages required (uses Python standard library only).",
		);
		console.error(
			"\x1b[31m──────────────────────────────────────────────────────────────────\x1b[0m",
		);
		process.exit(1);
	}

	return pyStatus.cmd;
}

if (require.main === module) {
	runCheck();
}

module.exports = {
	checkNodeVersion,
	checkPythonVersion,
	getInstallSuggestion,
	runCheck,
};
