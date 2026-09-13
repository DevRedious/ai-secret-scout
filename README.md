<div align="center">
  <pre>
 █████╗ ██╗   ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
██╔══██╗██║   ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
███████║██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
██╔══██║██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
██║  ██║██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
╚═╝  ╚═╝╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
       ◈  A I   S E C R E T   S C O U T  ◈
  </pre>

  <h2>AI Secret Scout (<code>aiscout</code>) — v2.4.3</h2>

  <p align="center">
    <!-- Row 1: tech & platform badges -->
    <a href="https://socket.dev/npm/package/ai-secret-scout"><img src="https://badge.socket.dev/npm/package/ai-secret-scout" alt="Socket Badge"></a>
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&amp;logoColor=white" alt="Python 3.10+">
    <img src="https://img.shields.io/badge/Interface-Full--Screen%20TUI-06B6D4?logo=gnometerminal&amp;logoColor=white" alt="Full-Screen TUI">
    <img src="https://img.shields.io/badge/Dependencies-Zero%20External-22c55e?logo=python&amp;logoColor=white" alt="Zero Dependencies">
    <img src="https://img.shields.io/badge/Watchdog-Real--Time%20%26%20Desktop%20Alerts-F59E0B?logo=airplayaudio&amp;logoColor=white" alt="Real-Time Watchdog">
    <img src="https://img.shields.io/badge/Safe%20Restore-Backup%20Manager-7C3AED?logo=securityscorecard&amp;logoColor=white" alt="Safe Restore">
    <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20WSL-0078D6?logo=windows&amp;logoColor=white" alt="Linux | Windows | WSL">
  </p>

  <p align="center">
    <!-- Row 2: audited AI ecosystems -->
    <img src="https://img.shields.io/badge/Claude%20Code-Audited-D97706?logo=anthropic&amp;logoColor=white" alt="Claude Code">
    <img src="https://img.shields.io/badge/Antigravity-Audited-4285F4?logo=google&amp;logoColor=white" alt="Antigravity">
    <img src="https://img.shields.io/badge/OpenAI%20Codex-Audited-10A37F?logo=openai&amp;logoColor=white" alt="Codex">
    <img src="https://img.shields.io/badge/GitHub%20Copilot-Audited-000000?logo=githubcopilot&amp;logoColor=white" alt="GitHub Copilot">
    <img src="https://img.shields.io/badge/Cursor%20%26%20Aider-Audited-8B5CF6" alt="Cursor &amp; Aider">
  </p>

  <p align="center">
    <i>Audit, real-time background monitoring (Watchdog), desktop notifications, heuristic secret detection, and safe redaction for AI coding assistant histories.</i>
  </p>

  <p align="center">
    <b>🇬🇧 English documentation</b> | <b><a href="./README.fr.md">🇫🇷 Documentation en français</a></b>
  </p>
</div>

---

## 📑 Table of Contents
1. [Why this project?](#-why-this-project)
2. [Key Highlights of v2.4.0](#-key-highlights-of-v240)
3. [Quickstart](#-quickstart)
4. [TUI Interface & Navigation](#-tui-interface--navigation)
5. [Real-Time Watchdog & Desktop Notifications](#-real-time-watchdog--desktop-notifications)
6. [Backup & Restore Manager (`Safe Restore`)](#-backup--restore-manager-safe-restore)
7. [Audited AI Ecosystems](#-audited-ai-ecosystems)
8. [Detection Engine & Signatures (18 built-in + Custom)](#-detection-engine--signatures-18-built-in--custom)
9. [Custom Rules Configuration (`rules.json`)](#-custom-rules-configuration-rulesjson)
10. [Anti-False-Positive Heuristics](#-anti-false-positive-heuristics)
11. [Safe Sanitization & Redaction (`Safe Redact`)](#-safe-sanitization--redaction-safe-redact)
12. [Keyboard Shortcuts & Controls](#-keyboard-shortcuts--controls)
13. [Scripting / CLI Mode & Automation](#-scripting--cli-mode--automation)
14. [Technical Architecture](#-technical-architecture)

---

## 🔍 Why this project?

When using autonomous coding assistants (**Claude Code**, **Google Antigravity / Gemini CLI**, **OpenAI Codex**, **GitHub Copilot CLI**, **Cursor**, **Aider**), language models persist complete conversation transcripts and execution logs in your local user directory (`~/.claude`, `~/.gemini`, etc.).

### The Problem
1. **Passive secret leakage**: When an agent runs a terminal command (e.g., `infisical secrets`, `ssh`, `curl`, or a script loading `.env`), raw terminal outputs and environment dumps are stored in plain text in local log files.
2. **Active prompt leakage**: When a developer pastes an API key, personal access token, or password directly into an AI chat session, that credential remains written to disk forever.
3. **Lack of native cleanup**: Even when an AI assistant warns you about a leaked secret in conversation, it **never** retroactively purges or redacts that value from disk history.
4. **Invisible persistence**: Stored secrets remain silently exposed to local malware, accidental cloud backups, dotfile synchronizations, or repository sharing.

**AI Secret Scout (`aiscout`)** solves this critical security gap: it scans and monitors all AI assistant histories across your system, attributes every detected secret to its **originating project**, identifies its **exact usage context**, and allows surgical **safe redaction** with automated backups and instant rollback capabilities.

---

## 🌟 Key Highlights of v2.4.0

* **🪟 Native Windows Support (Windows 10 & 11)**:
  * Full native terminal support via Python's standard `msvcrt` library (PowerShell, Command Prompt CMD, Windows Terminal).
  * Native background desktop toast notifications via PowerShell WinForms (zero extra window popups).
  * Auto-discovery of Windows-specific AI storage directories (`%APPDATA%\Cursor`, `%APPDATA%\Claude`, `%USERPROFILE%\.claude`, etc.).

* **🌐 Real-Time Bi-Directional Language Switching (`[L]`)**:
  * Live toggle between English and French at any point via the `[L]` key in TUI.
  * CLI parameter: `--lang en` or `--lang fr` (or `-l en` / `-l fr`).
  * Automatic locale detection on startup (`fr` on French systems, `en` on all international systems).

* **📡 Real-Time Continuous Monitoring (Watchdog Mode)**:
  * Watches AI session files for additions or modifications with near-zero CPU usage.
  * Sends immediate **native desktop notifications** (`notify-send` on Linux / KDE / GNOME, native PowerShell toasts on Windows).
  * Live visual heartbeat `🟢 [WATCHDOG ACTIVE]` with a rolling real-time event log.
  * Available via TUI menu `[8]` or direct CLI command: `aiscout --watch`.

* **↩️ Backup & Restore Manager (`Safe Restore`)**:
  * Dedicated interactive TUI table to inspect all `.bak` backup files created during redactions.
  * Individual surgical restoration (`[R]`), batch rollback of all originals (`[A]`), or definitive backup purge (`[P]`).
  * Dedicated CLI commands: `aiscout --restore` and `aiscout --clean-backups`.

* **🔍 Interactive Live Search (`/`) & Dynamic Sorting (`S`/`D`/`O`) in TUI**:
  * `/` key: Instant inline search bar (filters live across category, tool, project, path, or secret value).
  * Dynamic sorting shortcuts:
    * `S`: Sort by descending severity (`🔴 CRITICAL` > `🟡 HIGH` > `🔵 MEDIUM`).
    * `D`: Sort by session timestamp / freshness (most recent first).
    * `O`: Sort alphabetically by AI tool.
  * Fast reset via `Backspace` or `Esc`.

* **⚙️ Custom Rules Engine & 4 New Built-in Signatures**:
  * Automatically loads user-defined regex rules from `~/.config/aiscout/rules.json`.
  * 4 new enterprise signatures included out of the box:
    * **GitLab Personal Access Token** (`glpat-[0-9a-zA-Z_\-]{20,}`)
    * **HuggingFace Access Token** (`hf_[a-zA-Z0-9]{34,}`)
    * **Resend API Key** (`re_[a-zA-Z0-9_\-]{24,}`)
    * **Supabase / JWT Secret** (`eyJ...`)
  * CLI inspection command: `aiscout --list-rules` showcasing all 18 built-in patterns plus custom rules.

---

## 🚀 Quickstart

> [!TIP]
> **Cross-Platform Support**: `aiscout` runs natively on **Linux** (Wayland & X11), **Windows 10/11** (PowerShell, Command Prompt, Windows Terminal), and **WSL / WSL2**. Zero external dependencies required.

### 🐧 Linux, macOS & WSL / WSL2
```bash
# ⚡ Instant execution without prior installation
npx ai-secret-scout
# or using bun
bunx ai-secret-scout

# 📦 Permanent global installation (recommended)
npm install -g ai-secret-scout
# or using bun
bun add -g ai-secret-scout

# Launch
aiscout
```

### 🪟 Windows 10 & 11 (PowerShell, CMD, Windows Terminal)
```powershell
# ⚡ Instant execution without prior installation
npx ai-secret-scout

# 📦 Permanent global installation
npm install -g ai-secret-scout

# Launch
aiscout
```
> **Windows Prerequisite**: Python 3.10+ must be present on PATH. If not installed, run: `winget install Python.Python.3.12` or download from [python.org](https://www.python.org/downloads/).

### 🛠️ Common CLI Commands
```bash
# Launch real-time background watchdog with desktop notifications
aiscout --watch

# Restore all original files from .bak backups
aiscout --restore

# Permanently purge all .bak backup files
aiscout --clean-backups

# List all active detection rules (built-in + custom)
aiscout --list-rules

# Force language (English or French)
aiscout --lang en
```

The application automatically switches your terminal to an alternate screen buffer (`\033[?1049h`). Upon exit (`Q`), your original terminal prompt and history are seamlessly restored without visual leftovers.

---

## 🎨 TUI Interface & Navigation

`aiscout` features a standalone, dependency-free terminal user interface (built with standard Python library modules) that dynamically adjusts to your terminal geometry without truncation or phantom scrolling.

### 1. Central Hub & Dashboard

```text
 ◈ AISCOUT v2.4.3 │ User : dev_redious │ Host : workstation                12/09/2026 22:30

                 █████╗ ██╗   ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
                ██╔══██╗██║   ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
                ███████║██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
                ██╔══██║██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
                ██║  ██║██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
                ╚═╝  ╚═╝╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   

               ◈  A I   S E C R E T S   A U D I T   &   R E D A C T I O N  ◈
                Claude Code • Antigravity / Gemini • Codex • GitHub Copilot • Cursor

           [ 🔴 19 CRITICAL │ 🟡 1 HIGH │ 🔵 1 MEDIUM ]  ◈  TOTAL : 21 EXPOSED SECRETS 

        ║  ▶  [1]  🔍   RUN FULL AUDIT ACROSS ALL AI SESSIONS                          ║
        │     [2]  📋   SECRET EXPLORER (INTERACTIVE TUI TABLE)                       │
        │     [3]  👁️    REVEAL MODE (TOGGLE PLAIN-TEXT VALUES)                        │
        │     [4]  🏷️    FILTER BY AI TOOL OR PROJECT                                  │
        │     [5]  💾   EXPORT AUDIT REPORT (MARKDOWN / JSON)                         │
        │     [6]  🛡️    SAFE SANITIZATION & REDACTION                                 │
        │     [7]  ↩️    BACKUPS & RESTORE MANAGER (.BAK)                              │
        │     [8]  📡   REAL-TIME WATCHDOG (LIVE ALERTS)                              │
        │     [9]  🚪   EXIT APPLICATION                                              │

        ╭─ SELECTED ACTION ───────────────────────────────────────────────────────────╮
        │  💡  Browse through detected credentials with keyboard controls and inspect │
        ╰─────────────────────────────────────────────────────────────────────────────╯

  [↑/↓] Navigate  │  [Enter] Confirm  │  [1-9] Direct Jump  │  [L] Language (EN/FR)  │  [Q] Quit
```

### 2. Secret Explorer (Interactive Table, Dynamic Sorting & Search)

The interactive table allows fluid inspection of all detected secrets with multi-criteria sorting and instantaneous full-text filtering:

```text
 ◈ AISCOUT v2.4.3 │ User : dev_redious │ Host : workstation                12/09/2026 22:30

   📋 SECRET EXPLORER (1/21) — Mode : MASKED 🛡️ │ Sort : Severity (🔴 > 🟡 > 🔵)

 #   │ SEVERITY   │ CATEGORY                     │ AI TOOL            │ PROJECT                │ SECRET VALUE           
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 1   │ 🔴 CRITICAL │ Private Key (SSH/RSA/ECC)    │ Claude Code        │ ~                      │ ----****************...
 2   │ 🔴 CRITICAL │ Private Key (SSH/RSA/ECC)    │ Claude Code        │ ~                      │ ----****************...
 3   │ 🔴 CRITICAL │ GitHub Token (PAT/Fine-Gr)   │ Claude Code        │ ~/Documents/Dev/App... │ ghp_****************...
 4   │ 🔴 CRITICAL │ Infisical / Coolify Token    │ Claude Code        │ ~/Documents/Dev/App... │ st.4****************...
 5   │ 🟡 HIGH     │ Discord Bot Token            │ Claude Code        │ ~/Documents/Dev/App... │ MTE2****************...
 6   │ 🔵 MEDIUM   │ Password passed via CLI      │ Claude Code        │ ~/Documents/Dev/App... │ pass****************...
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  [↑/↓] Navigate │ [Enter] Card │ [/] Search │ [S/D/O] Sort │ [R] Reveal │ [C] Redact │ [Q] Back
```

#### Interactive Full-Text Search (`/`)
Pressing `/` opens an inline prompt directly in the status bar. The table updates dynamically with every keystroke:

```text
 ◈ AISCOUT v2.4.3 │ User : dev_redious │ Host : workstation                12/09/2026 22:30

   📋 SECRET EXPLORER (1/3) — Mode : MASKED 🛡️ │ Sort : Severity (🔴 > 🟡 > 🔵)
         🔍 Active filter: "github" (3 matching secrets) │ [Backspace/Esc] Clear 

 #   │ SEVERITY   │ CATEGORY                     │ AI TOOL            │ PROJECT                │ SECRET VALUE           
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 1   │ 🔴 CRITICAL │ GitHub Token (PAT/Fine-Gr)   │ Claude Code        │ ~/Documents/Dev/App... │ ghp_****************...
 2   │ 🔴 CRITICAL │ GitHub Token (PAT/Fine-Gr)   │ Claude Code        │ ~/Documents/Dev/App... │ ghp_****************...
 3   │ 🔴 CRITICAL │ GitHub Token (PAT/Fine-Gr)   │ Antigravity (Gemi) │ Antigravity Session    │ ghp_****************...
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  [↑/↓] Navigate │ [Enter] Card │ [/] Search │ [S/D/O] Sort │ [R] Reveal │ [C] Redact │ [Q] Back
```

### 3. Detailed Audit Card (Modal Card)

Pressing `Enter` on any row displays a full diagnostic modal card highlighting the source file, context, and remediation recommendations:

```text
 ◈ AISCOUT v2.4.3 │ User : dev_redious │ Host : workstation                12/09/2026 22:30

   ╭──────────────────────────────────────────────────────────────────────────────────╮
   │  AUDIT CARD FOR DETECTED SECRET                                                  │
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  Category       : Private Key (SSH / RSA / ECC)                                  │
   │  Severity       : CRITICAL                                                       │
   │  AI Tool        : Claude Code                                                    │
   │  Origin Project : ~                                                              │
   │  Session Date   : 2026-08-20 14:06                                               │
   │  Location       : 20b45f26-98f1-4273-a834-32243f11d067.jsonl:23                  │
   │  Context        : Tool output execution (bash command, .env, or infisical output)│
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  PLAIN VALUE    : -----BEGIN OPENSSH PRIVATE KEY-----                            │
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  Log Excerpt    : │ SECRET NAME                        │ SECRET VALUE            │
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  Recommended    : 1. Rotate the compromised key or token immediately.            │
   │  Action         : 2. Redact this log entry with [C] to erase residual traces.    │
   ╰──────────────────────────────────────────────────────────────────────────────────╯

  [C] Redact this secret  │  [Esc] or [Q] Return to list
```

### 4. Real-Time Scan Spinner & Progress Gauge

During scans, redactions, or reports generation, an animated 100ms spinner displays current scan phase and progress percentage:

```text
 ◈ AISCOUT v2.4.3 │ User : dev_redious │ Host : workstation                12/09/2026 22:30

                 █████╗ ██╗   ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
                ██╔══██╗██║   ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
                ███████║██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
                ██╔══██║██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
                ██║  ██║██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
                ╚═╝  ╚═╝╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   

               ⚡ SECURITY SCAN IN PROGRESS...

   ╭──────────────────────────────────────────────────────────────────╮
   │   ⠹  [▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▱▱▱▱▱▱▱▱▱▱▱]   58%                         │
   │   Scanning : Infisical / Coolify Token                           │
   ╰──────────────────────────────────────────────────────────────────╯

  Please wait while inspecting session histories...
```

### 🌟 TUI Engine Strengths
* **Cross-Platform Arrow & Input Decoder**: Native non-blocking keyboard polling (`msvcrt` on Windows, POSIX `termios`/`tty`/`select` on Linux/macOS) with 100ms lookahead absorbing all ANSI escape variants (`\x1b[A`, `\x1b[B`, `\x1bOA`, `\x1bOB`, Linux console, Shift/Ctrl modifiers).
* **Auto-Adaptive Layout**:
  * Fixed top bar at **line 1**.
  * Fixed bottom status bar at **last terminal line**.
  * Height ≥ 42: Double-bordered full-width menu cards (`╔══════╗`).
  * Height 27–41: Compact highlighted bar buttons with contextual explanation box.
  * Height < 27: Ultra-dense header ensuring all actions remain accessible.
* **Unicode Width Precision**: Incorporates character width metrics (`unicodedata.east_asian_width`) to guarantee pixel-perfect vertical border alignment with multi-byte emojis.

---

## 📡 Real-Time Watchdog & Desktop Notifications

The **Watchdog** mode turns `aiscout` into a background sentinel:

```text
 ◈ AISCOUT v2.4.3 │ User : dev_redious │ Host : workstation                12/09/2026 22:21

            📡 REAL-TIME MONITORING (WATCHDOG)  │  🟢 [ACTIVE SENTINEL]
        Detects active AI sessions writing to disk and sends instant desktop alerts

   ╭──────────────────────────────────────────────────────────────────────────────╮
   │ Monitored Files : 5498 │ Live Scans : 14 │ Alerts Triggered : 0              │
   ╰──────────────────────────────────────────────────────────────────────────────╯

   ╭─ 📜 ROLLING EVENT LOG (14 events) ───────────────────────────────────────────╮
   │  [22:20:10] 🚀 Sentinel started — 5498 AI history files monitored            │
   │  [22:20:45] ℹ️  Verified clean modification: history.jsonl                   │
   │  [22:21:02] ⚠️ ALERT : GitHub Token (CRITICAL) in Claude Code (~/AppProject)  │
   ╰──────────────────────────────────────────────────────────────────────────────╯

  [Q] or [Esc] Stop monitoring and return to main menu
```

### How it Works
1. **Lightweight Polling**: Inspects filesystem modification timestamps (`mtime`) across AI log directories without expensive full disk scans.
2. **Targeted Scan**: Upon detecting a modified or newly created file, only that specific file is scanned on the fly via `scan_single_file()`.
3. **Native Desktop Alerts**: Triggers `notify-send` with `critical` urgency on Linux desktop environments (KDE Plasma Wayland, GNOME) or native non-intrusive PowerShell toast notifications on Windows.
4. **Audible Alert**: Fires terminal bell sound (`\a`) on critical secret detections.

---

## ↩️ Backup & Restore Manager (`Safe Restore`)

TUI Menu `[7]` provides complete control over backup files created prior to sanitization:

```text
 ◈ AISCOUT v2.4.3 │ User : dev_redious │ Host : workstation                12/09/2026 22:22

              ↩️  SAFE RESTORE & BACKUP MANAGER (.BAK)
           Restore original files before redaction or purge stale backup copies.

 #   │ SOURCE FILE                      │ AI TOOL              │ SIZE       │ BACKUP DATE       
──────────────────────────────────────────────────────────────────────────────────────────
 1   │ 20b45f26-98f1-4273-a834...jsonl  │ Claude Code          │ 412.3 KB   │ 12/09/2026 22:15  
 2   │ history.jsonl                    │ Antigravity (Gemini) │ 84.1 KB    │ 12/09/2026 21:50  
──────────────────────────────────────────────────────────────────────────────────────────

  [↑/↓] Navigate │ [R] Restore selected │ [A] Restore all │ [P] Purge (.bak) │ [Esc] Back
```

* **`[R]` Restore selected file**: Replaces the sanitized file with its pre-redaction copy and deletes the `.bak`.
* **`[A]` Restore all**: Restores all detected backups across all projects in a single confirmed action.
* **`[P]` Purge backups**: Permanently deletes all `.bak` files to finalize sanitization and free disk space.

---

## 📁 Audited AI Ecosystems

`aiscout` automatically scans history paths across your workstation:

| AI Coding Assistant | Monitored Paths | File Types |
| :--- | :--- | :--- |
| **Claude Code** | `~/.claude/projects/`, `~/.claude/history.jsonl`, `~/.claude/handoff/` | `JSONL`, `JSON` |
| **Google Antigravity / Gemini CLI** | `~/.gemini/antigravity-cli/brain/`, `~/.gemini/antigravity-cli/history.jsonl`, `conversations/` | `JSONL`, `JSON` |
| **OpenAI Codex CLI** | `~/.codex/sessions/`, `~/.codex/history.jsonl` | `JSONL`, `JSON` |
| **GitHub Copilot CLI** | `~/.copilot/session-state/` | `JSON`, `LOG` |
| **Cursor & Aider** | `~/.cursor/projects/`, `~/.cursor/plans/`, `.aider.chat.history.md` | `JSON`, `MD` |

---

## 🛡️ Detection Engine & Signatures (18 built-in + Custom)

| Category | Severity | Detection Pattern Signature |
| :--- | :---: | :--- |
| **GitHub Token (PAT / Fine-Grained)** | 🔴 **CRITICAL** | `ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}` |
| **GitLab Personal Access Token** *(New)* | 🔴 **CRITICAL** | `glpat-[0-9a-zA-Z_\-]{20,}` |
| **HuggingFace Token** *(New)* | 🔴 **CRITICAL** | `hf_[a-zA-Z0-9]{34,}` |
| **Private Key (SSH / RSA / ECC / PEM)** | 🔴 **CRITICAL** | `-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----` |
| **Stripe Secret Key** | 🔴 **CRITICAL** | `sk_live_[0-9a-zA-Z]{24,}`, `rk_live_[0-9a-zA-Z]{24,}` |
| **Database URI (with Credentials)** | 🔴 **CRITICAL** | `postgres://user:password@host`, `mysql://...`, `mongodb://...` |
| **Infisical / Coolify Token** | 🔴 **CRITICAL** | `st.[a-f0-9]{24}.[a-f0-9]{64}`, `inf_sec_...`, `inf_tok_...` |
| **Resend API Key** *(New)* | 🟡 **HIGH** | `re_[a-zA-Z0-9_\-]{24,}` |
| **Supabase / JWT Secret** *(New)* | 🟡 **HIGH** | `eyJ[a-zA-Z0-9_-]{10,}\.eyJ...` |
| **Anthropic API Key** | 🟡 **HIGH** | `sk-ant-api03-[A-Za-z0-9_-]{30,}` |
| **OpenAI API Key** | 🟡 **HIGH** | `sk-proj-[A-Za-z0-9_-]{32,}` |
| **AWS Access Key** | 🟡 **HIGH** | `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}` |
| **Discord Bot Token** | 🟡 **HIGH** | `[MN][A-Za-z\d]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,39}` |
| **Slack Token** | 🟡 **HIGH** | `xox[baprs]-[0-9a-zA-Z]{10,48}` |
| **Tailscale Auth Key** | 🟡 **HIGH** | `tskey-auth-[a-zA-Z0-9_-]{20,}` |
| **Sensitive Environment Variable** | 🟡 **HIGH** | `PGPASSWORD=...`, `MYSQL_PWD=...`, `API_KEY=...` |
| **Password in Chat Prompt** | 🟡 **HIGH** | `"my password is ..."`, `"pwd: ..."` |
| **Password passed via CLI Command** | 🔵 **MEDIUM** | `sshpass -p ...`, `mysql -p...`, `--password ...` |

---

## ⚙️ Custom Rules Configuration (`rules.json`)

You can define custom, organization-specific secret patterns in:
`~/.config/aiscout/rules.json`

```json
{
  "_comment": "Add your custom detection rules here. Format: Rule Name: {regex, severity, description}",
  "Internal Corporate Token": {
    "regex": "\\bcorp_sec_[a-zA-Z0-9]{24,}\\b",
    "severity": "CRITICAL",
    "description": "Internal secret token granting access to corporate services."
  },
  "Partner API Key": {
    "regex": "\\bpartner_live_[a-z0-9]{32}\\b",
    "severity": "HIGH",
    "description": "B2B partner API authentication key."
  }
}
```

All custom rules are automatically tagged with a `[CUSTOM]` badge and incorporated into scans, the watchdog, and the interactive TUI table.

---

## 🧠 Anti-False-Positive Heuristics

To avoid noisy alerts and false positives, `aiscout` runs 5 mathematical filters:

1. **Shannon Entropy Calculation ($H$)**:
   $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
   Strings with low entropy (< 3.2 bits/symbol) are automatically discarded.
2. **Character Class Diversity**:
   Random tokens must combine at least 3 distinct character classes (lowercase, uppercase, digits, symbols).
3. **Contextual Placeholder Blacklist**:
   Explicit exclusion of documentation examples: `your_token`, `dummy`, `example`, `change_me`, `sk-ant-xxx`, etc.
4. **Cryptographic Block Verification for Private Keys**:
   Isolated string mentions are ignored; only complete key blocks containing headers, body, and footers (`-----END ...`) are reported.
5. **Mirror Anti-Self-Detection Shield**:
   `aiscout` ignores its own regex signatures, binary scripts, and previously redacted tags (`[REDACTED_BY_AISCOUT]`).

---

## 🛡️ Safe Sanitization & Redaction (`Safe Redact`)

* **Targeted Surgical Redaction (`[C]`)**: In-place replacement of a single compromised secret with `[REDACTED_BY_AISCOUT]`.
* **Global Redaction (`[6]`)**: One-click sanitization of all detected compromised sessions.
* **Guaranteed `.bak` Backups**: An exact copy is saved prior to any file modification.
* **Safe Restore Integration**: Every redaction can be undone on demand from the `[7]` backup screen.

---

## 🕹️ Keyboard Shortcuts & Controls

### Main Dashboard Hub
| Key | Action |
| :--- | :--- |
| `↑` / `↓` or `k` / `j` | Move selection cursor |
| `Enter` / `Space` / `→` | Execute highlighted action |
| `1` to `9` | Direct numeric menu jump |
| `L` | Switch Language on the fly (`EN` / `FR`) |
| `Q` or `Ctrl+C` | Clean exit |

### Secret Explorer (TUI Table)
| Key | Action |
| :--- | :--- |
| `↑` / `↓` or `k` / `j` | Navigate row by row |
| `PageUp` / `PageDown` | Scroll by full page |
| `Enter` | Open **detailed audit card** |
| `/` | **Interactive live search** (category, tool, project, path, value) |
| `S` | **Sort by severity** (`🔴 CRITICAL` > `🟡 HIGH` > `🔵 MEDIUM`) |
| `D` | **Sort by date** (most recent sessions first) |
| `O` | **Sort by AI tool** (alphabetical) |
| `Backspace` / `Esc` | Clear active search query |
| `R` | Toggle **Masked** (`ghp_****...`) vs **Plain-Text** |
| `C` | Surgically redact the highlighted secret |
| `Q` or `Esc` | Return to main dashboard |

### Backup Manager (`Safe Restore`) & Watchdog
| Key | Action |
| :--- | :--- |
| `R` *(Backups)* | Restore selected `.bak` file |
| `A` *(Backups)* | Restore all original backup files |
| `P` *(Backups)* | Permanently purge all `.bak` copies |
| `Q` or `Esc` | Exit screen and return to dashboard |

---

## ⚙️ Scripting / CLI Mode & Automation

```bash
# Run headless terminal scan
aiscout --scan

# Launch real-time background watchdog with desktop notifications
aiscout --watch

# Restore all original files from .bak backups
aiscout --restore

# Permanently purge all backup files
aiscout --clean-backups

# List all 18 active rules plus user custom rules
aiscout --list-rules

# Print plain-text unmasked secrets
aiscout --reveal

# Output raw JSON stream for automated CI/CD pipelines
aiscout --json | jq '.[] | select(.severity == "CRITICAL")'

# Export report directly to Markdown or JSON file
aiscout --export ~/Documents/audit_secrets.md
aiscout --export ~/Documents/audit_secrets.json

# Scan a custom user home directory
aiscout --home-dir /home/other_user
```

---

## 🏗️ Technical Architecture

* **Core Engine**: Pure Python 3.10+ standard library (`os`, `sys`, `re`, `json`, `unicodedata`, `shutil`, `argparse`, `subprocess`, with `msvcrt` on Windows and `termios`/`tty`/`select` on POSIX).
* **Zero External Dependencies**: Zero `pip` dependencies required.
* **Supported Platforms**: **Linux** (native Wayland / X11), **Windows 10/11** (native PowerShell, CMD, Windows Terminal), and **WSL / WSL2**.
* **Notification System**: Auto-detects `notify-send` on Linux and native PowerShell toast notifications on Windows.
* **Configuration Path**: `~/.config/aiscout/rules.json` (or `%APPDATA%\aiscout\rules.json` on Windows).
* **Zero Telemetry**: 100% local execution, zero outbound network traffic, complete privacy guarantee.

---

<div align="center">
  <sub>Built with care for the autonomous AI coding era • Released under the MIT License</sub>
</div>
