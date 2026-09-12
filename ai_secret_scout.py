#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
AI SECRET SCOUT (aiscout) — v2.1.0 Full TUI Application
Audit & Détection de secrets en clair dans les transcriptions & mémoires d'IA
Interface TUI plein écran avec logo centré, menus larges, flèches et animations
Compatible : Claude Code, Antigravity/Gemini CLI, Codex, Copilot CLI, Cursor, Aider
===============================================================================
"""

import sys
import os
import re
import time
import json
import math
import shutil
import platform
import argparse
import subprocess
import unicodedata
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import msvcrt
    # Active les séquences d'échappement VT100 / ANSI sous console Windows
    os.system("")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
    except Exception:
        pass
else:
    import select
    import termios
    import tty

VERSION = "2.4.2"

# --- INTERNATIONALISATION (I18N) ---
def detect_default_lang() -> str:
    """Détecte la langue système par défaut (FR si locale fr, sinon EN)."""
    env = os.getenv("LC_ALL") or os.getenv("LC_MESSAGES") or os.getenv("LANG") or ""
    return "fr" if "fr" in env.lower() else "en"

CURRENT_LANG = detect_default_lang()

def set_lang(lang: Optional[str]):
    global CURRENT_LANG
    if not lang:
        CURRENT_LANG = detect_default_lang()
    else:
        CURRENT_LANG = "fr" if lang.lower().startswith("fr") else "en"

def get_lang() -> str:
    return CURRENT_LANG

def toggle_lang() -> str:
    global CURRENT_LANG
    CURRENT_LANG = "fr" if CURRENT_LANG == "en" else "en"
    return CURRENT_LANG

SEV_TRANSLATIONS = {
    "en": {"CRITIQUE": "CRITICAL", "ÉLEVÉ": "HIGH", "MOYEN": "MEDIUM", "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"},
    "fr": {"CRITICAL": "CRITIQUE", "HIGH": "ÉLEVÉ", "MEDIUM": "MOYEN", "CRITIQUE": "CRITIQUE", "ÉLEVÉ": "ÉLEVÉ", "MOYEN": "MOYEN"}
}

def fmt_severity(sev: str, lang: Optional[str] = None) -> str:
    l = lang or CURRENT_LANG
    norm_sev = SEV_TRANSLATIONS["fr"].get(sev, sev)
    if l == "en":
        return SEV_TRANSLATIONS["en"].get(norm_sev, norm_sev)
    return norm_sev

RULE_I18N = {
    "en": {
        "GitHub Token (PAT / Fine-Grained)": {
            "name": "GitHub Token (PAT / Fine-Grained)",
            "desc": "Personal or OAuth GitHub access token (repository read/write permissions)."
        },
        "Clé Privée (SSH / RSA / ECC)": {
            "name": "Private Key (SSH / RSA / ECC)",
            "desc": "Private cryptographic key header for server authentication or signing."
        },
        "Discord Bot Token": {
            "name": "Discord Bot Token",
            "desc": "Discord Bot authentication token (server or bot control)."
        },
        "Anthropic API Key": {
            "name": "Anthropic API Key",
            "desc": "Claude (Anthropic) API key for model inference."
        },
        "OpenAI API Key": {
            "name": "OpenAI API Key",
            "desc": "OpenAI API key for GPT / embeddings."
        },
        "AWS Access Key": {
            "name": "AWS Access Key",
            "desc": "Amazon Web Services IAM or STS access key ID."
        },
        "Stripe Secret Key": {
            "name": "Stripe Secret Key",
            "desc": "Stripe secret payment processing API key."
        },
        "Slack Token": {
            "name": "Slack Token",
            "desc": "Slack bot or user workspace integration token."
        },
        "Tailscale Auth Key": {
            "name": "Tailscale Auth Key",
            "desc": "Tailscale mesh VPN authentication node key."
        },
        "Infisical / Coolify Token": {
            "name": "Infisical / Coolify Token",
            "desc": "Infisical secrets vault service token or Coolify API token."
        },
        "Base de données (URI avec mot de passe)": {
            "name": "Database URI (with Credentials)",
            "desc": "Database connection URI exposing username and plain-text password."
        },
        "Variable d'environnement sensible": {
            "name": "Sensitive Environment Variable",
            "desc": "Environment variable assigning sensitive credentials in terminal."
        },
        "Mot de passe passé en commande CLI": {
            "name": "Password passed via CLI Command",
            "desc": "Password passed directly into dedicated CLI commands (sshpass, mysql, --password)."
        },
        "Mot de passe en clair dans le Prompt": {
            "name": "Password in Chat Prompt",
            "desc": "Plain-text password provided by user in conversation prompt."
        },
        "GitLab Personal Access Token": {
            "name": "GitLab Personal Access Token",
            "desc": "GitLab personal access token for repository access."
        },
        "HuggingFace Token": {
            "name": "HuggingFace Token",
            "desc": "HuggingFace user access token for models and datasets."
        },
        "Resend API Key": {
            "name": "Resend API Key",
            "desc": "Resend transactional email service API key."
        },
        "Supabase / JWT Secret": {
            "name": "Supabase / JWT Secret",
            "desc": "JSON Web Token (JWT) secret or Supabase service role key."
        }
    }
}

def get_rule_display(name: str, default_desc: str = "", lang: Optional[str] = None) -> Tuple[str, str]:
    l = lang or CURRENT_LANG
    if l == "en" and name in RULE_I18N["en"]:
        return RULE_I18N["en"][name]["name"], RULE_I18N["en"][name]["desc"]
    return name, default_desc

USAGE_CONTEXT_I18N = {
    "en": {
        "Texte consigné en session": "Text logged in session",
        "Sortie d'outil exécuté (commande bash, .env ou infisical)": "Executed tool output (bash command, .env, or infisical)",
        "Message / Prompt utilisateur direct": "Direct user message / prompt",
        "Réponse / Génération de l'assistant IA": "AI assistant response / generation",
        "Prompt utilisateur Antigravity": "Antigravity user prompt",
        "Raisonnement / Réponse du modèle": "Model reasoning / response",
        "Sortie de commande Infisical ou dump de secrets": "Infisical command output or secret dump",
        "Commande bash 'export' d'une variable d'environnement": "Bash 'export' of environment variable",
        "Transmission d'identifiant dans la conversation": "Credential shared within conversation",
        "Session Codex CLI": "Codex CLI session",
        "Session Copilot CLI": "Copilot CLI session"
    }
}

def fmt_usage_context(ctx: str, lang: Optional[str] = None) -> str:
    l = lang or CURRENT_LANG
    if l == "en":
        return USAGE_CONTEXT_I18N["en"].get(ctx, ctx)
    return ctx

I18N_STRINGS = {
    "fr": {
        "app_subtitle": "◈  A U D I T   D E S   S E C R E T S   E N   C L A I R   D A N S   L E S   I A  ◈",
        "user_label": "Utilisateur",
        "host_label": "Machine",
        "lbl_crit": "CRITIQUES",
        "lbl_high": "ÉLEVÉS",
        "lbl_med": "MOYENS",
        "lbl_total_exposed": "SECRETS EXPOSÉS",
        "filter_active": "Filtres actifs : {filts} ({count} éléments)",
        "action_selected": "ACTION SÉLECTIONNÉE",
        "bottom_nav_hub": "[↑/↓] Naviguer  │  [Entrée] Valider  │  [1-9] Accès direct  │  [L] Langue ({lang})  │  [Q] Quitter",
        "scan_in_progress": "⚡ AUDIT DE SÉCURITÉ EN COURS D'EXÉCUTION...",
        "scan_wait": "Veuillez patienter pendant l'analyse...",
        "scan_done_title": "✔ AUDIT TERMINÉ AVEC SUCCÈS !",
        "scan_done_sub": "{count} secrets réels identifiés dans vos sessions.",
        "scan_return_hint": "[Entrée] ou [Espace] pour revenir au tableau de bord",
        "explorer_title": "📋 EXPLORATEUR DE SECRETS ({curr}/{total}) — Mode : {mode} │ Tri : {sort}",
        "mode_masked": "MASQUÉ 🛡️",
        "mode_revealed": "EN CLAIR ⚠️",
        "sort_sev": "Sévérité (🔴 > 🟡 > 🔵)",
        "sort_date": "Date (Plus récents)",
        "sort_tool": "Outil IA (A-Z)",
        "search_active": " 🔍 Recherche active : \"{q}\" ({count} secrets trouvés) │ [Backspace/Esc] Effacer ",
        "search_no_match": "Aucun secret ne correspond à la recherche : \"{q}\"",
        "search_reset_hint": "[Backspace] ou [Esc] pour réinitialiser la recherche.",
        "filter_no_match": "Aucun secret ne correspond aux filtres actuels.",
        "search_prompt": "🔍 Rechercher (catégorie, outil, projet, valeur)",
        "col_num": "#",
        "col_severity": "SÉVÉRITÉ",
        "col_category": "CATÉGORIE",
        "col_tool": "OUTIL IA",
        "col_project": "PROJET",
        "col_secret": "VALEUR DU SECRET",
        "bottom_nav_table": "[↑/↓] Naviguer │ [Entrée] Fiche │ [/] Chercher │ [S/D/O] Trier │ [R] Mode │ [C] Caviarder │ [Q] Retour",
        "card_title": "FICHE D'AUDIT DU SECRET DÉTECTÉ",
        "card_cat": "Catégorie",
        "card_sev": "Sévérité",
        "card_tool": "Outil IA",
        "card_proj": "Projet d'origine",
        "card_date": "Date session",
        "card_loc": "Emplacement",
        "card_ctx": "Contexte",
        "card_plain_val": "VALEUR EN CLAIR",
        "card_masked_val": "VALEUR MASQUÉE",
        "card_log": "Extrait Log",
        "card_action_label": "Action conseillée",
        "card_action_1": "1. Procéder à la rotation de la clé/identifiant.",
        "card_action_2": "2. Caviarder ce fichier avec [C] pour effacer la trace du disque.",
        "card_bottom": "[C] Caviarder ce secret  │  [Esc] ou [Q] Retour à la liste",
        "confirm_redact_title": "⚠️  CONFIRMATION DE CAVIARDAGE SÉCURISÉ ⚠️",
        "confirm_redact_replace": "La valeur sera remplacée par '[REDACTED_BY_AISCOUT]'.",
        "confirm_redact_bak": "Une sauvegarde automatique (.bak) sera créée.",
        "confirm_redact_bottom": "[O] Confirmer l'assainissement  │  [Annuler] Toute autre touche",
        "redact_success": "✔ SECRET CAVIARDÉ AVEC SUCCÈS !",
        "redact_file_cleaned": "Fichier assaini : {file}",
        "redact_bak_created": "Sauvegarde créée : {bak}",
        "global_redact_title": "🛡️  ASSAINISSEMENT GLOBAL DES SESSIONS",
        "global_redact_msg1": "Cette action va remplacer {count} secrets par '[REDACTED_BY_AISCOUT]'",
        "global_redact_msg2": "dans tous les fichiers de transcription concernés.",
        "global_redact_msg3": "Une sauvegarde (.bak) sera créée pour chaque fichier.",
        "global_redact_bottom": "[O] Lancer l'assainissement global  │  [Annuler] Toute autre touche",
        "global_redact_progress": "🛡️  ASSAINISSEMENT EN COURS D'EXÉCUTION...",
        "global_redact_wait": "Veuillez patienter pendant le remplacement sécurisé...",
        "global_redact_done": "✔ ASSAINISSEMENT TERMINÉ AVEC SUCCÈS !",
        "global_redact_done_sub": "{count} secrets caviardés et remplacés par [REDACTED_BY_AISCOUT].",
        "global_redact_done_bak": "Des sauvegardes automatiques (.bak) ont été créées.",
        "backups_title": "↩️  GESTIONNAIRE DES SAUVEGARDES & RESTAURATION (.BAK)",
        "backups_desc": "Restaurer les fichiers originaux avant caviardage ou purger les sauvegardes.",
        "backups_none": "✔ Aucune sauvegarde (.bak) détectée.",
        "backups_none_sub": "Tous vos fichiers de sessions IA sont dans leur état normal.",
        "col_src": "FICHIER SOURCE",
        "col_size": "TAILLE",
        "col_bak_date": "DATE SAUVEGARDE",
        "backups_bottom": "[↑/↓] Naviguer │ [R] Restaurer sélection │ [A] Tout restaurer │ [P] Purger (.bak) │ [Esc] Retour",
        "watchdog_title": "📡 SURVEILLANCE EN TEMPS RÉEL (WATCHDOG)",
        "watchdog_active": "🟢 [VEILLE ACTIVE]",
        "watchdog_scanning": "🔘 [ANALYSE EN COURS]",
        "watchdog_desc": "Détecte les sessions IA en écriture et notifie instantanément sur le bureau KDE Plasma",
        "watchdog_stats": " Fichiers écoutés : {files} │ Scans live : {scans} │ Alertes déclenchées : {alerts} ",
        "watchdog_log_title": " 📜 JOURNAL DES ÉVÉNEMENTS RÉCENTS ({count} logs) ",
        "watchdog_started": "🚀 Surveillance démarrée — {files} fichiers d'historique IA sous écoute.",
        "watchdog_bottom": "[Q] ou [Esc] Quitter la surveillance et revenir au menu principal",
        "cli_rules_title": "RÈGLES DE DÉTECTION ACTIVES",
        "cli_rule_name": "NOM DE LA RÈGLE",
        "cli_rule_desc": "DESCRIPTION",
        "cli_restore_success": "✔ {count} fichier(s) restauré(s) avec succès depuis leurs sauvegardes .bak.",
        "cli_restore_none": "Aucun fichier de sauvegarde .bak à restaurer.",
        "cli_clean_success": "✔ {count} fichier(s) .bak supprimé(s) définitivement.",
        "cli_clean_none": "Aucun fichier de sauvegarde .bak à nettoyer.",
        "cli_watch_stopped": "✔ Surveillance Watchdog arrêtée.",
        "cli_tui_closed": "✔ AI Secret Scout fermé. Vos sessions sont sécurisées.",
        "cli_desc": "AI Secret Scout - Détecteur et protecteur de secrets dans les historiques d'assistants IA",
        "cli_help_scan": "Exécute un scan et affiche le tableau directement",
        "cli_help_watch": "Surveille en temps réel les sessions IA et envoie des alertes bureau",
        "cli_help_restore": "Restaure l'ensemble des fichiers originaux depuis leurs sauvegardes .bak",
        "cli_help_clean": "Supprime définitivement tous les fichiers de sauvegarde .bak",
        "cli_help_rules": "Liste toutes les règles de détection actives (intégrées et personnalisées)",
        "cli_help_reveal": "Affiche les secrets en clair dans le terminal",
        "cli_help_json": "Sortie brute au format JSON",
        "cli_help_export": "Exporte le rapport dans un fichier Markdown ou JSON",
        "cli_help_homedir": "Spécifie un répertoire utilisateur alternatif à analyser",
        "cli_user_config": "Fichier de configuration utilisateur : {path}",
        "cli_export_success": "Rapport exporté avec succès dans {path}",
        "watchdog_alert_log": "⚠️ ALERTE : {cat} ({sev}) dans {tool} ({proj})",
        "watchdog_clean_log": "ℹ️  {act} vérifiée saine : {file}",
        "watchdog_act_creation": "Création",
        "watchdog_act_modification": "Modification",
        "notif_title": "Secret Détecté",
        "notif_sec": "Secret",
        "menu_1": ("AUDIT COMPLET DES SESSIONS IA", "Scanne toutes les transcriptions et mémoires d'IA (Claude, Gemini, etc.)"),
        "menu_2": ("EXPLORATEUR DE SECRETS (TABLEAU TUI)", "Naviguer au clavier dans la liste des secrets détectés et inspecter"),
        "menu_3": ("MODE RÉVÉLATION (VALEURS EN CLAIR)", "Basculer l'affichage des secrets en clair ou masqué (ghp_**** vs brut)"),
        "menu_4": ("FILTRER PAR OUTIL IA OU PROJET", "Isoler les secrets de Claude Code, Antigravity, ou d'un projet précis"),
        "menu_5": ("EXPORTER LE DOSSIER D'AUDIT", "Générer un rapport d'audit soigné et certifié en Markdown ou JSON"),
        "menu_6": ("ASSAINISSEMENT & CAVIARDAGE SÉCURISÉ", "Remplacer les secrets par [REDACTED_BY_AISCOUT] avec backup auto .bak"),
        "menu_7": ("GESTIONNAIRE DES BACKUPS (.BAK)", "Inspecter, restaurer des fichiers d'origine ou purger les sauvegardes"),
        "menu_8": ("SURVEILLANCE TEMPS RÉEL (WATCHDOG)", "Surveiller les sessions en continu avec alertes bureau natives"),
        "menu_9": ("QUITTER L'APPLICATION", "Fermer AI Secret Scout et restaurer proprement votre terminal")
    },
    "en": {
        "app_subtitle": "◈  A I   S E C R E T S   A U D I T   &   R E D A C T I O N  ◈",
        "user_label": "User",
        "host_label": "Host",
        "lbl_crit": "CRITICAL",
        "lbl_high": "HIGH",
        "lbl_med": "MEDIUM",
        "lbl_total_exposed": "EXPOSED SECRETS",
        "filter_active": "Active filters: {filts} ({count} items)",
        "action_selected": "SELECTED ACTION",
        "bottom_nav_hub": "[↑/↓] Navigate  │  [Enter] Confirm  │  [1-9] Direct Jump  │  [L] Language ({lang})  │  [Q] Quit",
        "scan_in_progress": "⚡ SECURITY SCAN IN PROGRESS...",
        "scan_wait": "Please wait while inspecting session histories...",
        "scan_done_title": "✔ SCAN COMPLETED SUCCESSFULLY!",
        "scan_done_sub": "{count} real secrets identified across your AI sessions.",
        "scan_return_hint": "[Enter] or [Space] to return to dashboard",
        "explorer_title": "📋 SECRET EXPLORER ({curr}/{total}) — Mode : {mode} │ Sort : {sort}",
        "mode_masked": "MASKED 🛡️",
        "mode_revealed": "PLAIN-TEXT ⚠️",
        "sort_sev": "Severity (🔴 > 🟡 > 🔵)",
        "sort_date": "Date (Most recent)",
        "sort_tool": "AI Tool (A-Z)",
        "search_active": " 🔍 Active filter: \"{q}\" ({count} matching secrets) │ [Backspace/Esc] Clear ",
        "search_no_match": "No secrets matched the query: \"{q}\"",
        "search_reset_hint": "[Backspace] or [Esc] to reset search.",
        "filter_no_match": "No secrets matched the active filters.",
        "search_prompt": "🔍 Search (category, tool, project, value)",
        "col_num": "#",
        "col_severity": "SEVERITY",
        "col_category": "CATEGORY",
        "col_tool": "AI TOOL",
        "col_project": "PROJECT",
        "col_secret": "SECRET VALUE",
        "bottom_nav_table": "[↑/↓] Navigate │ [Enter] Card │ [/] Search │ [S/D/O] Sort │ [R] Reveal │ [C] Redact │ [Q] Back",
        "card_title": "AUDIT CARD FOR DETECTED SECRET",
        "card_cat": "Category",
        "card_sev": "Severity",
        "card_tool": "AI Tool",
        "card_proj": "Origin Project",
        "card_date": "Session Date",
        "card_loc": "Location",
        "card_ctx": "Context",
        "card_plain_val": "PLAIN VALUE",
        "card_masked_val": "MASKED VALUE",
        "card_log": "Log Excerpt",
        "card_action_label": "Recommended Action",
        "card_action_1": "1. Rotate the compromised key or credential immediately.",
        "card_action_2": "2. Redact this log file with [C] to purge residual traces from disk.",
        "card_bottom": "[C] Redact this secret  │  [Esc] or [Q] Return to list",
        "confirm_redact_title": "⚠️  CONFIRM SAFE REDACTION ⚠️",
        "confirm_redact_replace": "The secret value will be replaced by '[REDACTED_BY_AISCOUT]'.",
        "confirm_redact_bak": "An automatic backup copy (.bak) will be created.",
        "confirm_redact_bottom": "[Y] Confirm redaction  │  [Cancel] Any other key",
        "redact_success": "✔ SECRET REDACTED SUCCESSFULLY!",
        "redact_file_cleaned": "Sanitized file : {file}",
        "redact_bak_created": "Backup created : {bak}",
        "global_redact_title": "🛡️  GLOBAL SESSIONS SANITIZATION",
        "global_redact_msg1": "This action will replace {count} secrets with '[REDACTED_BY_AISCOUT]'",
        "global_redact_msg2": "across all affected conversation transcripts and log files.",
        "global_redact_msg3": "An exact backup (.bak) will be preserved for each file.",
        "global_redact_bottom": "[Y] Run global sanitization  │  [Cancel] Any other key",
        "global_redact_progress": "🛡️  SANITIZATION IN PROGRESS...",
        "global_redact_wait": "Please wait while securely replacing credentials...",
        "global_redact_done": "✔ SANITIZATION COMPLETED SUCCESSFULLY!",
        "global_redact_done_sub": "{count} secrets redacted and replaced by [REDACTED_BY_AISCOUT].",
        "global_redact_done_bak": "Automatic backup files (.bak) have been created.",
        "backups_title": "↩️  SAFE RESTORE & BACKUP MANAGER (.BAK)",
        "backups_desc": "Restore original files before redaction or permanently purge backups.",
        "backups_none": "✔ No backup files (.bak) detected.",
        "backups_none_sub": "All AI session files are in their original clean state.",
        "col_src": "SOURCE FILE",
        "col_size": "SIZE",
        "col_bak_date": "BACKUP DATE",
        "backups_bottom": "[↑/↓] Navigate │ [R] Restore selected │ [A] Restore all │ [P] Purge (.bak) │ [Esc] Back",
        "watchdog_title": "📡 REAL-TIME MONITORING (WATCHDOG)",
        "watchdog_active": "🟢 [WATCHDOG ACTIVE]",
        "watchdog_scanning": "🔘 [SCANNING]",
        "watchdog_desc": "Detects active AI sessions writing to disk and sends instant desktop alerts",
        "watchdog_stats": " Monitored Files : {files} │ Live Scans : {scans} │ Alerts Triggered : {alerts} ",
        "watchdog_log_title": " 📜 ROLLING EVENT LOG ({count} events) ",
        "watchdog_started": "🚀 Sentinel started — {files} AI history files monitored.",
        "watchdog_bottom": "[Q] or [Esc] Stop monitoring and return to main menu",
        "cli_rules_title": "ACTIVE DETECTION RULES",
        "cli_rule_name": "RULE NAME",
        "cli_rule_desc": "DESCRIPTION",
        "cli_restore_success": "✔ {count} file(s) successfully restored from .bak backup copies.",
        "cli_restore_none": "No .bak backup files found to restore.",
        "cli_clean_success": "✔ {count} .bak backup file(s) permanently deleted.",
        "cli_clean_none": "No .bak backup files to clean.",
        "cli_watch_stopped": "✔ Watchdog monitoring stopped.",
        "cli_tui_closed": "✔ AI Secret Scout closed. Your sessions are secure.",
        "cli_desc": "AI Secret Scout - Detect and redact leaked credentials in AI assistant session histories",
        "cli_help_scan": "Run scan and display table directly",
        "cli_help_watch": "Monitor AI sessions in real-time and send desktop alerts",
        "cli_help_restore": "Restore all original files from .bak backups",
        "cli_help_clean": "Permanently delete all .bak backup files",
        "cli_help_rules": "List all active detection rules (built-in and custom)",
        "cli_help_reveal": "Display unmasked secrets in terminal",
        "cli_help_json": "Raw JSON output",
        "cli_help_export": "Export report to Markdown or JSON file",
        "cli_help_homedir": "Specify an alternative user directory to scan",
        "cli_user_config": "User configuration file: {path}",
        "cli_export_success": "Report successfully exported to {path}",
        "watchdog_alert_log": "⚠️ ALERT: {cat} ({sev}) in {tool} ({proj})",
        "watchdog_clean_log": "ℹ️  {act} verified clean: {file}",
        "watchdog_act_creation": "Creation",
        "watchdog_act_modification": "Modification",
        "notif_title": "Secret Detected",
        "notif_sec": "Secret",
        "menu_1": ("RUN FULL AUDIT ACROSS ALL AI SESSIONS", "Scan all AI transcripts and memories (Claude, Gemini, Codex, etc.)"),
        "menu_2": ("SECRET EXPLORER (INTERACTIVE TUI TABLE)", "Browse and inspect detected credentials with keyboard controls"),
        "menu_3": ("REVEAL MODE (TOGGLE PLAIN-TEXT VALUES)", "Toggle plain-text vs masked display (ghp_**** vs raw)"),
        "menu_4": ("FILTER BY AI TOOL OR PROJECT", "Isolate secrets for Claude Code, Antigravity, or specific project"),
        "menu_5": ("EXPORT AUDIT REPORT (MARKDOWN / JSON)", "Generate clean audit reports in Markdown or JSON format"),
        "menu_6": ("SAFE SANITIZATION & REDACTION", "Replace secrets with [REDACTED_BY_AISCOUT] with auto .bak backup"),
        "menu_7": ("BACKUPS & RESTORE MANAGER (.BAK)", "Inspect, restore pre-redaction originals, or purge .bak files"),
        "menu_8": ("REAL-TIME WATCHDOG (LIVE ALERTS)", "Continuously monitor AI sessions with native desktop notifications"),
        "menu_9": ("EXIT APPLICATION", "Close AI Secret Scout and cleanly restore your terminal")
    }
}

def t(key: str, **kwargs) -> Any:
    l = CURRENT_LANG
    d = I18N_STRINGS.get(l, I18N_STRINGS["en"])
    val = d.get(key, I18N_STRINGS["en"].get(key, key))
    if isinstance(val, str) and kwargs:
        try:
            return val.format(**kwargs)
        except Exception:
            return val
    return val

# --- PALETTE ANSI & STYLES ---
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    INVERSE = "\033[7m"
    
    # Couleurs de texte
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    
    # Arrière-plans
    BG_BLUE = "\033[44m"
    BG_CYAN = "\033[46m"
    BG_DARK = "\033[100m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_MAGENTA = "\033[45m"

# --- LOGO ASCII ---
ASCII_LOGO = [
    "█████╗ ██╗   ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗",
    "██╔══██╗██║   ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝",
    "███████║██║   ███████╗██║     ██║   ██║██║   ██║   ██║   ",
    "██╔══██║██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   ",
    "██║  ██║██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   ",
    "╚═╝  ╚═╝╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   "
]

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# --- RÈGLES DE DÉTECTION ---
PATTERNS = {
    "GitHub Token (PAT / Fine-Grained)": {
        "regex": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b",
        "severity": "CRITIQUE",
        "description": "Jeton d'accès GitHub personnel ou OAuth (droits en lecture/écriture sur les dépôts)."
    },
    "Clé Privée (SSH / RSA / ECC)": {
        "regex": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)? PRIVATE KEY-----",
        "severity": "CRITIQUE",
        "description": "En-tête de clé cryptographique privée permettant l'authentification serveur ou la signature."
    },
    "Discord Bot Token": {
        "regex": r"\b[MN][A-Za-z\d]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,39}\b",
        "severity": "ÉLEVÉ",
        "description": "Jeton d'authentification pour un Bot Discord (contrôle de serveur ou d'application)."
    },
    "Anthropic API Key": {
        "regex": r"\bsk-ant-(?:api\d\d-)?[A-Za-z0-9_-]{30,}\b",
        "severity": "ÉLEVÉ",
        "description": "Clé d'API Claude (Anthropic) permettant de consommer des tokens d'inférence."
    },
    "OpenAI API Key": {
        "regex": r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b",
        "severity": "ÉLEVÉ",
        "description": "Clé d'API OpenAI pour GPT / embeddings."
    },
    "AWS Access Key": {
        "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "severity": "ÉLEVÉ",
        "description": "Identifiant de clé d'accès IAM ou STS Amazon Web Services."
    },
    "Stripe Secret Key": {
        "regex": r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b",
        "severity": "CRITIQUE",
        "description": "Clé secrète d'API bancaire Stripe."
    },
    "Slack Token": {
        "regex": r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
        "severity": "ÉLEVÉ",
        "description": "Jeton d'intégration de bot ou d'utilisateur Slack."
    },
    "Tailscale Auth Key": {
        "regex": r"\btskey-auth-[a-zA-Z0-9_-]{20,}\b",
        "severity": "ÉLEVÉ",
        "description": "Clé d'authentification réseau VPN maillé Tailscale."
    },
    "Infisical / Coolify Token": {
        "regex": r"\bst\.[a-f0-9]{24}\.[a-f0-9]{64}\b|\binf_sec_[A-Za-z0-9_-]{20,}\b|\binf_tok_[A-Za-z0-9_-]{20,}\b",
        "severity": "CRITIQUE",
        "description": "Jeton de coffre-fort de secrets Infisical ou jeton API Coolify."
    },
    "Base de données (URI avec mot de passe)": {
        "regex": r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-\.]+:(?!(?:password|root|postgres|admin|\$\{[^\}]+\}|<[^>]+>|\*+|\[|\%|\bYOUR_))[^\s@\"'`:]+@[a-zA-Z0-9_\-\.]+",
        "severity": "CRITIQUE",
        "description": "Chaîne de connexion de base de données contenant identifiant et mot de passe en clair."
    },
    "Variable d'environnement sensible": {
        "regex": r"(?i)\b(?:PGPASSWORD|MYSQL_PWD|DB_PASSWORD|AUTH_TOKEN|API_KEY|SECRET_KEY|COOLIFY_API_TOKEN)=([\"']?[A-Za-z0-9_\-@#$%^&+=!]{8,}[\"']?)",
        "severity": "ÉLEVÉ",
        "description": "Affectation de mot de passe ou secret via variable d'environnement dans un terminal."
    },
    "Mot de passe passé en commande CLI": {
        "regex": r"(?i)\b(?:--password[\s=]+|sshpass\s+-p\s*|mysql\s+(?:-[a-zA-Z0-9_]+\s+)*-p)([\"']?[A-Za-z0-9_\-@#$%^&+=!]{6,}[\"']?)",
        "severity": "MOYEN",
        "description": "Mot de passe transmis directement dans une commande dédiée (ex. sshpass, mysql, --password)."
    },
    "Mot de passe en clair dans le Prompt": {
        "regex": r"(?i)(?:mon mot de passe est|le mot de passe (?:est|c'est)|mdp\s*[:=]|mot de passe\s*[:=]|my password is|the password is|password\s*[:=])\s*([\"']?[A-Za-z0-9_\-@#$%^&+=!]{6,}[\"']?)",
        "severity": "ÉLEVÉ",
        "description": "Mot de passe rédigé directement par l'utilisateur dans l'invite de dialogue avec l'IA."
    },
    "GitLab Personal Access Token": {
        "regex": r"\bglpat-[a-zA-Z0-9_\-]{20,}\b",
        "severity": "CRITIQUE",
        "description": "Jeton d'accès personnel GitLab pour dépôts de code."
    },
    "HuggingFace Token": {
        "regex": r"\bhf_[a-zA-Z0-9]{34,}\b",
        "severity": "CRITIQUE",
        "description": "Jeton d'accès HuggingFace pour modèles IA et datasets."
    },
    "Resend API Key": {
        "regex": r"\bre_[a-zA-Z0-9_\-]{24,}\b",
        "severity": "ÉLEVÉ",
        "description": "Clé d'API du service d'envoi d'emails Resend."
    },
    "Supabase / JWT Secret": {
        "regex": r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
        "severity": "ÉLEVÉ",
        "description": "Jeton d'authentification JSON Web Token ou clé de service Supabase."
    }
}

# --- CONFIGURATION ET RÈGLES PERSONNALISÉES (rules.json) ---
if IS_WINDOWS and os.getenv("APPDATA"):
    CONFIG_DIR = Path(os.getenv("APPDATA")) / "aiscout"
else:
    CONFIG_DIR = Path.home() / ".config" / "aiscout"
CUSTOM_RULES_FILE = CONFIG_DIR / "rules.json"

def load_custom_rules() -> Dict[str, Dict[str, str]]:
    """Charge les règles personnalisées de l'utilisateur depuis rules.json."""
    if not CUSTOM_RULES_FILE.exists():
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            sample = {
                "_comment": "Ajoutez vos règles personnalisées ici. Format: Nom: {regex, severity, description}",
                "Exemple Jeton Interne": {
                    "regex": r"\bcorp_sec_[a-zA-Z0-9]{24,}\b",
                    "severity": "ÉLEVÉ",
                    "description": "Exemple de jeton interne propre à votre entreprise."
                }
            }
            with open(CUSTOM_RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(sample, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
        return {}

    try:
        with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = {}
        for k, v in data.items():
            if k.startswith("_") or not isinstance(v, dict):
                continue
            if "regex" in v and "severity" in v:
                rules[f"{k} [CUSTOM]"] = {
                    "regex": v["regex"],
                    "severity": v.get("severity", "MOYEN"),
                    "description": v.get("description", "Règle personnalisée utilisateur.")
                }
        return rules
    except Exception:
        return {}


def send_desktop_notification(title: str, message: str, severity: str = "normal"):
    """Envoie une notification de bureau native sous Linux / KDE / GNOME ou Windows 10/11."""
    if IS_WINDOWS:
        clean_title = title.replace('"', '`"').replace("'", "''")
        clean_msg = message.replace('"', '`"').replace("'", "''").replace("\n", " ")
        ps_script = (
            f'[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms"); '
            f'$objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon; '
            f'$objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Shield; '
            f'$objNotifyIcon.BalloonTipIcon = "Warning"; '
            f'$objNotifyIcon.BalloonTipTitle = "{clean_title}"; '
            f'$objNotifyIcon.BalloonTipText = "{clean_msg}"; '
            f'$objNotifyIcon.Visible = $True; '
            f'$objNotifyIcon.ShowBalloonTip(5000); '
            f'Start-Sleep -Seconds 1; '
            f'$objNotifyIcon.Dispose()'
        )
        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass
        return

    if shutil.which("notify-send"):
        urgency = "critical" if severity in ("CRITIQUE", "ÉLEVÉ") else "normal"
        try:
            subprocess.run([
                "notify-send",
                "-u", urgency,
                "-a", "AI Secret Scout",
                "-i", "security-high",
                title,
                message
            ], capture_output=True, timeout=2)
        except Exception:
            pass


PLACEHOLDER_KEYWORDS = [
    "your_key", "your_token", "your_password", "your_api_key", "your_secret",
    "example", "placeholder", "dummy", "fake", "xxxx", "00000", "12345", "test",
    "abcdef", "sk-ant-xxx", "ghp_xxx", "password", "secret", "undefined", "null",
    "none", "true", "false", "localhost", "admin", "root", "dev", "prod", "change_me",
    "changeme", "foobar", "redacted", "token_here", "key_here", "sample", "postgres_db",
    "ostgres", "postgres"
]

COMMON_WORDS_FR_EN = {
    "compromis", "obligatoire", "requis", "introuvable", "invalide", "correct",
    "incorrect", "temporaire", "modifie", "modifié", "supprime", "supprimé",
    "necessaire", "nécessaire", "unique", "manquant", "visible", "invisible",
    "cache", "caché", "simple", "complexe", "expire", "expiré", "active", "activé",
    "different", "différent", "identique", "partage", "partagé", "inconnu",
    "chiffre", "chiffré", "confidentiel", "protege", "protégé", "efface", "effacé",
    "renseigne", "renseigné", "argument", "uploads", "desktop", "libsqlite", "ostgres",
    "postgres", "mysql", "database", "root", "admin", "required", "compromised",
    "invalid", "default", "optional", "mandatory", "provided", "accepted"
}


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def count_character_classes(text: str) -> int:
    return sum([
        any(c.islower() for c in text),
        any(c.isupper() for c in text),
        any(c.isdigit() for c in text),
        any(not c.isalnum() for c in text)
    ])


def display_len(s: str) -> int:
    """Calcule la largeur réelle d'affichage dans le terminal en tenant compte des codes ANSI et des emojis."""
    clean = re.sub(r"\033\[[0-9;]*[a-zA-Z]", "", s)
    length = 0
    for ch in clean:
        w = unicodedata.east_asian_width(ch)
        if w in ("W", "F"):
            length += 2
        elif unicodedata.category(ch) == "Mn":
            length += 0
        else:
            length += 1
    return length


def read_key() -> str:
    """Lecture robuste des frappes clavier (Linux / macOS / Windows natif)."""
    if IS_WINDOWS:
        while not msvcrt.kbhit():
            time.sleep(0.02)
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            # Touche spéciale sous Windows (flèches, pagination, etc.)
            code = msvcrt.getwch()
            arrows = {
                "H": "UP",
                "P": "DOWN",
                "K": "LEFT",
                "M": "RIGHT",
                "I": "PAGE_UP",
                "Q": "PAGE_DOWN",
                "G": "HOME",
                "O": "END",
                "S": "DELETE"
            }
            return arrows.get(code, "")
        if ch in ("\r", "\n"):
            return "ENTER"
        if ch == " ":
            return "SPACE"
        if ch == "\t":
            return "TAB"
        if ch in ("\x08", "\x7f"):
            return "BACKSPACE"
        if ch == "\x1b":
            return "ESC"
        if ch == "\x03":
            return "CTRL_C"
        return ch

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        data = os.read(fd, 1)
        if data == b"\x1b":
            # Si un octet Escape arrive, on attend jusqu'à 100ms pour lire la suite de la séquence ANSI
            while True:
                r, _, _ = select.select([fd], [], [], 0.1)
                if r:
                    chunk = os.read(fd, 32)
                    data += chunk
                    if len(data) >= 3:
                        break
                else:
                    break

        if data.startswith(b"\x1b"):
            # Séquences de flèches universelles (standard ANSI, application mode, Linux VT, modifiers)
            if data in (b"\x1b[A", b"\x1bOA", b"\x1b[[A") or (data.startswith(b"\x1b[") and data.endswith(b"A")):
                return "UP"
            if data in (b"\x1b[B", b"\x1bOB", b"\x1b[[B") or (data.startswith(b"\x1b[") and data.endswith(b"B")):
                return "DOWN"
            if data in (b"\x1b[C", b"\x1bOC", b"\x1b[[C") or (data.startswith(b"\x1b[") and data.endswith(b"C")):
                return "RIGHT"
            if data in (b"\x1b[D", b"\x1bOD", b"\x1b[[D") or (data.startswith(b"\x1b[") and data.endswith(b"D")):
                return "LEFT"
            if data in (b"\x1b[5~", b"\x1b[[5~"):
                return "PAGE_UP"
            if data in (b"\x1b[6~", b"\x1b[[6~"):
                return "PAGE_DOWN"
            if data in (b"\x1b[H", b"\x1b[1~"):
                return "HOME"
            if data in (b"\x1b[F", b"\x1b[4~"):
                return "END"
            if data == b"\x1b":
                return "ESC"

        if data in (b"\r", b"\n"):
            return "ENTER"
        if data == b" ":
            return "SPACE"
        if data == b"\t":
            return "TAB"
        if data in (b"\x7f", b"\x08"):
            return "BACKSPACE"
        if data == b"\x03":
            return "CTRL_C"

        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)



class Finding:
    def __init__(self, category: str, secret_raw: str, file_path: str, line_no: int,
                 tool: str, project: str, usage_context: str, snippet: str,
                 timestamp: Optional[str] = None, severity: Optional[str] = None,
                 description: Optional[str] = None):
        self.category = category
        self.secret_raw = secret_raw
        self.secret_masked = self.mask(secret_raw)
        self.file_path = file_path
        self.line_no = line_no
        self.tool = tool
        self.project = project
        self.usage_context = usage_context
        self.snippet = snippet.strip()
        self.timestamp = timestamp or "Inconnu"
        self.severity = severity or PATTERNS.get(category, {}).get("severity", "MOYEN")
        self.description = description or PATTERNS.get(category, {}).get("description", "")

    def display_category(self, lang: Optional[str] = None) -> str:
        name, _ = get_rule_display(self.category, default_desc=self.description, lang=lang)
        return name

    def display_severity(self, lang: Optional[str] = None) -> str:
        return fmt_severity(self.severity, lang=lang)

    def display_usage_context(self, lang: Optional[str] = None) -> str:
        return fmt_usage_context(self.usage_context, lang=lang)

    @staticmethod
    def mask(val: str) -> str:
        s = val.strip().strip("'\"")
        if len(s) <= 8:
            return s[:2] + "****"
        return s[:4] + "*" * (min(len(s) - 8, 20)) + s[-4:]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.display_category(),
            "category_raw": self.category,
            "severity": self.display_severity(),
            "severity_raw": self.severity,
            "tool": self.tool,
            "project": self.project,
            "secret_masked": self.secret_masked,
            "secret_raw": self.secret_raw,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "timestamp": self.timestamp,
            "usage_context": self.display_usage_context(),
            "snippet": self.snippet,
            "description": self.description
        }


class ScoutEngine:
    def __init__(self, user_home: Optional[Path] = None):
        self.home = user_home or Path.home()
        self.rg_path = self._locate_ripgrep()
        self.patterns = dict(PATTERNS)
        self.patterns.update(load_custom_rules())
        self.findings: List[Finding] = []
        self._cwd_cache: Dict[str, str] = {}

    def _locate_ripgrep(self) -> Optional[str]:
        system_rg = shutil.which("rg")
        if system_rg:
            return system_rg
        cargo_rg = self.home / ".cargo" / "bin" / "rg"
        if cargo_rg.exists() and os.access(cargo_rg, os.X_OK):
            return str(cargo_rg)
        return None

    def get_target_directories(self) -> List[Path]:
        targets = [
            self.home / ".claude" / "projects",
            self.home / ".claude" / "history.jsonl",
            self.home / ".claude" / "handoff",
            self.home / ".gemini" / "antigravity-cli" / "brain",
            self.home / ".gemini" / "antigravity-cli" / "history.jsonl",
            self.home / ".gemini" / "antigravity-ide" / "conversations",
            self.home / ".codex" / "sessions",
            self.home / ".copilot" / "session-state",
            self.home / ".cursor" / "projects",
            self.home / ".cursor" / "plans",
            self.home / ".continue" / "sessions",
            self.home / ".aider.chat.history.md",
        ]
        # Emplacements Windows spécifiques (%APPDATA% et %USERPROFILE%)
        appdata = os.getenv("APPDATA")
        if appdata:
            ad = Path(appdata)
            targets.extend([
                ad / "Cursor" / "User" / "workspaceStorage",
                ad / "Claude" / "projects",
                ad / "Code" / "User" / "workspaceStorage"
            ])
        localappdata = os.getenv("LOCALAPPDATA")
        if localappdata:
            lad = Path(localappdata)
            targets.extend([
                lad / "Programs" / "cursor" / "resources"
            ])
        return [p for p in targets if p.exists()]

    def identify_tool(self, file_path: str) -> str:
        fp = str(file_path).lower().replace("\\", "/")
        if ".claude" in fp or "/claude/" in fp:
            return "Claude Code"
        elif ".gemini" in fp or "antigravity" in fp:
            return "Antigravity (Gemini)"
        elif ".codex" in fp:
            return "Codex"
        elif ".copilot" in fp:
            return "GitHub Copilot"
        elif ".cursor" in fp or "/cursor/" in fp:
            return "Cursor"
        elif ".continue" in fp:
            return "Continue.dev"
        elif "aider" in fp:
            return "Aider"
        return "Assistant IA Inconnu"

    def resolve_project(self, file_path: str) -> str:
        if file_path in self._cwd_cache:
            return self._cwd_cache[file_path]

        p = Path(file_path)
        if ".claude" in str(file_path) and p.suffix == ".jsonl":
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for _ in range(10):
                        line = f.readline()
                        if not line:
                            break
                        if '"cwd"' in line:
                            data = json.loads(line)
                            if "cwd" in data and data["cwd"]:
                                res = data["cwd"].replace(str(self.home), "~")
                                self._cwd_cache[file_path] = res
                                return res
            except Exception:
                pass

            parent_name = p.parent.name
            if parent_name.startswith("-"):
                clean = parent_name.lstrip("-").replace("-", "/")
                clean = clean.replace(str(self.home).lstrip("/"), "~")
                self._cwd_cache[file_path] = clean
                return clean

        if ".gemini" in str(file_path):
            brain_dir = p.parent
            while brain_dir.name != "brain" and brain_dir.parent != brain_dir:
                if (brain_dir / ".system_generated").exists():
                    self._cwd_cache[file_path] = f"Session Antigravity ({brain_dir.name[:8]})"
                    return self._cwd_cache[file_path]
                brain_dir = brain_dir.parent
            return "Espace Antigravity"

        if ".codex" in str(file_path):
            return "Session Codex CLI"
        if ".copilot" in str(file_path):
            return "Session Copilot CLI"
        if ".cursor" in str(file_path):
            return p.parent.name

        return str(p.parent).replace(str(self.home), "~")

    def determine_usage_context(self, raw_line: str, tool: str) -> Tuple[str, str]:
        line_clean = raw_line.strip()
        usage = "Texte consigné en session"
        try:
            data = json.loads(line_clean)
            if "type" in data:
                t = data.get("type")
                if t == "user":
                    msg = data.get("message", {})
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        for item in content:
                            if item.get("type") == "tool_result":
                                usage = "Sortie d'outil exécuté (commande bash, .env ou infisical)"
                                snip = str(item.get("content", ""))[:200]
                                return usage, snip
                    usage = "Message / Prompt utilisateur direct"
                elif t == "assistant":
                    usage = "Réponse / Génération de l'assistant IA"
            elif "step_index" in data:
                stype = data.get("type")
                if stype == "USER_INPUT":
                    usage = "Prompt utilisateur Antigravity"
                elif stype == "PLANNER_RESPONSE":
                    usage = "Raisonnement / Réponse du modèle"
        except Exception:
            pass

        if "infisical" in line_clean.lower():
            usage = "Sortie de commande Infisical ou dump de secrets"
        elif "export " in line_clean:
            usage = "Commande bash 'export' d'une variable d'environnement"
        elif "password" in line_clean.lower() or "mot de passe" in line_clean.lower():
            usage = "Transmission d'identifiant dans la conversation"

        snippet = line_clean[:180].replace("\n", " ").replace("\r", "")
        return usage, snippet

    def is_valid_secret(self, text: str, category: str = "", full_line: str = "") -> bool:
        t = text.strip().strip("'\"`")
        lower_t = t.lower()

        if len(t) < 6:
            return False

        if t.startswith("$") or t.startswith("<") or t.startswith("{{") or t.startswith("[") or t.startswith("("):
            return False
        if t.endswith(">") or t.endswith("]") or t.endswith(")") or t.endswith("}"):
            return False

        for ph in PLACEHOLDER_KEYWORDS:
            if ph in lower_t:
                return False
        if re.search(r"^(?:YOUR_|VOTRE_|SAMPLE_|MY_|TEST_|EXAMPLE_)[A-Z0-9_]+$", t, re.IGNORECASE):
            return False
        if re.search(r"_[A-Z]+_(?:KEY|TOKEN|SECRET|PASSWORD|HERE)$", t, re.IGNORECASE):
            return False

        if len(set(lower_t)) <= 2 and len(t) >= 6:
            return False

        if any(marker in full_line for marker in ["AI SECRET SCOUT", "[REDACTED_BY_AISCOUT]", "FICHE DÉTAILLÉE DU SECRET", "rapport_audit"]):
            return False

        if "Clé Privée" in category:
            if "END " not in full_line and "PRIVATE KEY" not in full_line.split(text)[-1]:
                return False

        if any(kw in category for kw in ["Prompt", "CLI", "commande", "sensible"]):
            if lower_t in COMMON_WORDS_FR_EN:
                return False

            classes = count_character_classes(t)
            entropy = calculate_entropy(t)

            if classes == 1:
                if t.isalpha():
                    return False
                if entropy < 3.0:
                    return False

            if classes == 2 and t.istitle() and t.isalpha():
                return False

        return True

    def scan(self, progress_callback=None) -> List[Finding]:
        self.findings = []
        targets = [str(t) for t in self.get_target_directories()]
        if not targets:
            return []

        if self.rg_path:
            total_cats = len(self.patterns)
            for idx, (cat_name, conf) in enumerate(self.patterns.items(), 1):
                if progress_callback:
                    progress_callback(idx, total_cats, f"Analyse : {cat_name}")
                cmd = [self.rg_path, "-H", "-n", "--no-heading", "--no-messages", "--glob", "!*.bak", "--glob", "!*.backup", "-e", conf["regex"]] + targets
                proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
                for line in proc.stdout.splitlines():
                    if not line:
                        continue
                    parts = line.split(":", 2)
                    if len(parts) < 3:
                        continue
                    fpath, lno_str, content = parts[0], parts[1], parts[2]
                    if "ai_secret_scout" in fpath or "scan_secrets" in fpath:
                        continue
                    try:
                        lno = int(lno_str)
                    except ValueError:
                        lno = 0

                    for m in re.finditer(conf["regex"], content):
                        raw = m.group(1) if m.groups() else m.group(0)
                        if not self.is_valid_secret(raw, category=cat_name, full_line=content):
                            continue
                        tool = self.identify_tool(fpath)
                        project = self.resolve_project(fpath)
                        usage, snippet = self.determine_usage_context(content, tool)
                        try:
                            mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
                        except Exception:
                            mtime = "Inconnu"

                        self.findings.append(Finding(
                            category=cat_name,
                            secret_raw=raw,
                            file_path=fpath,
                            line_no=lno,
                            tool=tool,
                            project=project,
                            usage_context=usage,
                            snippet=snippet,
                            timestamp=mtime,
                            severity=conf.get("severity", "MOYEN"),
                            description=conf.get("description", "")
                        ))
        else:
            all_files = []
            for t in targets:
                tp = Path(t)
                if tp.is_file():
                    all_files.append(tp)
                elif tp.is_dir():
                    for root, _, files in os.walk(tp):
                        for f in files:
                            if f.endswith((".jsonl", ".json", ".md")) and not f.endswith((".bak", ".backup")):
                                all_files.append(Path(root) / f)

            for idx, fpath in enumerate(all_files, 1):
                if progress_callback and idx % 10 == 0:
                    progress_callback(idx, len(all_files), f"Lecture : {fpath.name}")
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for lno, line in enumerate(f, 1):
                            for cat_name, conf in self.patterns.items():
                                for m in re.finditer(conf["regex"], line):
                                    raw = m.group(1) if m.groups() else m.group(0)
                                    if not self.is_valid_secret(raw, category=cat_name, full_line=line):
                                        continue
                                    tool = self.identify_tool(str(fpath))
                                    project = self.resolve_project(str(fpath))
                                    usage, snippet = self.determine_usage_context(line, tool)
                                    self.findings.append(Finding(
                                        category=cat_name,
                                        secret_raw=raw,
                                        file_path=str(fpath),
                                        line_no=lno,
                                        tool=tool,
                                        project=project,
                                        usage_context=usage,
                                        snippet=snippet,
                                        severity=conf.get("severity", "MOYEN"),
                                        description=conf.get("description", "")
                                    ))
                except Exception:
                    continue

        dedup_map: Dict[Tuple[str, str, str, int], Finding] = {}
        for f in self.findings:
            key = (f.category, f.secret_raw, f.file_path, f.line_no)
            if key not in dedup_map:
                dedup_map[key] = f
        self.findings = sorted(list(dedup_map.values()), key=lambda x: (x.severity != "CRITIQUE", x.severity != "ÉLEVÉ", x.category))
        return self.findings

    def scan_single_file(self, fpath: Path) -> List[Finding]:
        """Analyse unitairement un fichier pour y détecter des secrets."""
        if not fpath.exists() or not fpath.is_file() or str(fpath).endswith((".bak", ".backup")):
            return []
        findings = []
        tool = self.identify_tool(str(fpath))
        project = self.resolve_project(str(fpath))
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            mtime = "Inconnu"

        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for lno, line in enumerate(f, 1):
                    for cat_name, conf in self.patterns.items():
                        for m in re.finditer(conf["regex"], line):
                            raw = m.group(1) if m.groups() else m.group(0)
                            if not self.is_valid_secret(raw, category=cat_name, full_line=line):
                                continue
                            usage, snippet = self.determine_usage_context(line, tool)
                            findings.append(Finding(
                                category=cat_name,
                                secret_raw=raw,
                                file_path=str(fpath),
                                line_no=lno,
                                tool=tool,
                                project=project,
                                usage_context=usage,
                                snippet=snippet,
                                timestamp=mtime,
                                severity=conf.get("severity", "MOYEN"),
                                description=conf.get("description", "")
                            ))
        except Exception:
            pass
        return findings

    def redact_secret(self, finding: Finding) -> bool:
        target = Path(finding.file_path)
        if not target.exists():
            return False
        backup_file = target.with_suffix(target.suffix + ".bak")
        if not backup_file.exists():
            shutil.copy2(target, backup_file)
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            new_content = content.replace(finding.secret_raw, "[REDACTED_BY_AISCOUT]")
            with open(target, "w", encoding="utf-8") as f:
                f.write(new_content)
            return True
        except Exception:
            return False

    def list_backups(self) -> List[Path]:
        """Recherche et liste tous les fichiers de sauvegarde .bak dans les répertoires d'IA."""
        backups = []
        targets = self.get_target_directories()
        for t in targets:
            if t.is_file() and str(t).endswith(".bak"):
                backups.append(t)
            elif t.is_dir():
                for root, _, files in os.walk(t):
                    for f in files:
                        if f.endswith(".bak"):
                            backups.append(Path(root) / f)
        backups.sort(key=lambda p: os.path.getmtime(p) if p.exists() else 0, reverse=True)
        return backups

    def restore_backup(self, backup_path: Path) -> bool:
        """Restaure un fichier original depuis son fichier .bak et supprime le backup."""
        if not backup_path.exists() or not str(backup_path).endswith(".bak"):
            return False
        orig_path = Path(str(backup_path)[:-4])
        try:
            shutil.copy2(backup_path, orig_path)
            backup_path.unlink()
            return True
        except Exception:
            return False

    def restore_all_backups(self) -> int:
        """Restaure tous les fichiers .bak existants."""
        count = 0
        for b in self.list_backups():
            if self.restore_backup(b):
                count += 1
        return count

    def clean_backups(self) -> int:
        """Supprime définitivement tous les fichiers de sauvegarde .bak."""
        count = 0
        for b in self.list_backups():
            try:
                b.unlink()
                count += 1
            except Exception:
                pass
        return count


# --- GESTIONNAIRE D'AFFICHAGE PLEIN ÉCRAN (TUI ENGINE) ---
class ScoutTUI:
    def __init__(self, engine: ScoutEngine):
        self.engine = engine
        self.findings: List[Finding] = []
        self.active_filter_tool: Optional[str] = None
        self.active_filter_project: Optional[str] = None
        self.search_query: str = ""
        self.sort_mode: str = "severity"  # "severity", "date", "tool"
        self.reveal_mode: bool = False
        self.selected_menu_idx: int = 0
        self.selected_table_idx: int = 0

    @staticmethod
    def get_width() -> int:
        return shutil.get_terminal_size((90, 30)).columns

    @staticmethod
    def get_height() -> int:
        return shutil.get_terminal_size((90, 30)).lines

    def enter_tui(self):
        sys.stdout.write("\033[?1049h\033[?25l\033[2J")
        sys.stdout.flush()

    def exit_tui(self):
        sys.stdout.write("\033[?1049l\033[?25h")
        sys.stdout.flush()

    def center_line(self, text: str, width: int) -> str:
        vis = display_len(text)
        pad = max(0, (width - vis) // 2)
        return " " * pad + text

    def build_top_bar(self, width: int) -> str:
        user = os.getenv("USER") or os.getenv("USERNAME") or "user"
        host = platform.node() or "localhost"
        date_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        u_lbl = t("user_label")
        h_lbl = t("host_label")
        left = f" ◈ AISCOUT v{VERSION} │ {u_lbl} : {user} │ {h_lbl} : {host}"
        right = f"{date_str} "
        space = max(0, width - display_len(left) - display_len(right))
        return f"{C.BG_BLUE}{C.WHITE}{C.BOLD}{left}{' ' * space}{right}{C.RESET}"

    def build_bottom_bar(self, width: int, hint: str) -> str:
        content = f"  {hint}"
        space = max(0, width - display_len(content))
        return f"{C.BG_DARK}{C.WHITE}{content}{' ' * space}{C.RESET}"

    def prompt_input(self, prompt_label: str, initial: str = "") -> Optional[str]:
        """Saisie interactive inline sur la barre inférieure du TUI."""
        width = self.get_width()
        height = self.get_height()
        buf = list(initial)
        while True:
            cur_text = "".join(buf)
            prompt_line = f"  {prompt_label}: {cur_text}█"
            sp = max(0, width - display_len(prompt_line))
            rendered_bar = f"{C.BG_BLUE}{C.WHITE}{C.BOLD}{prompt_line}{' ' * sp}{C.RESET}"
            sys.stdout.write(f"\033[{height};1H{rendered_bar}")
            sys.stdout.flush()

            key = read_key()
            if key == "ENTER":
                return "".join(buf)
            elif key == "ESC":
                return None
            elif key == "BACKSPACE":
                if buf:
                    buf.pop()
            elif len(key) == 1 and key.isprintable():
                buf.append(key)

    def confirm_action(self, question: str) -> bool:
        """Demande une confirmation oui/non élégante."""
        width = self.get_width()
        height = self.get_height()
        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{C.YELLOW}{C.BOLD}⚠️  CONFIRMATION{C.RESET}", width))
        lines.append("")
        lines.append(self.center_line(f"{C.WHITE}{question}{C.RESET}", width))
        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, "[O/Y] Confirmer / Yes  │  [Annuler / Any other key]"))
        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()
        k = read_key()
        return k in ("o", "O", "y", "Y")

    def show_flash_message(self, message: str, color_code: str = C.GREEN):
        """Affiche un écran de notification ou statut temporaire."""
        width = self.get_width()
        height = self.get_height()
        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{color_code}{C.BOLD}{message}{C.RESET}", width))
        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, "[Enter] / [Space] to continue"))
        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()
        while read_key() not in ("ENTER", "SPACE", "ESC"):
            pass

    def toggle_language(self):
        new_lang = toggle_lang()
        msg = "Language switched to English (EN)" if new_lang == "en" else "Langue basculée en Français (FR)"
        self.show_flash_message(f"✔ {msg}", C.CYAN)

    def get_filtered_findings(self) -> List[Finding]:
        res = list(self.findings)
        if self.active_filter_tool:
            res = [f for f in res if f.tool == self.active_filter_tool]
        if self.active_filter_project:
            res = [f for f in res if f.project == self.active_filter_project]
        if self.search_query:
            q = self.search_query.lower()
            res = [
                f for f in res
                if q in f.category.lower()
                or q in f.display_category().lower()
                or q in f.tool.lower()
                or q in f.project.lower()
                or q in f.file_path.lower()
                or q in f.secret_raw.lower()
                or q in f.snippet.lower()
                or q in f.usage_context.lower()
                or q in f.display_usage_context().lower()
            ]
        if self.sort_mode == "severity":
            sev_weights = {"CRITIQUE": 0, "ÉLEVÉ": 1, "MOYEN": 2, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
            res.sort(key=lambda x: (sev_weights.get(x.severity, 3), x.category))
        elif self.sort_mode == "date":
            res.sort(key=lambda x: x.timestamp, reverse=True)
        elif self.sort_mode == "tool":
            res.sort(key=lambda x: (x.tool.lower(), x.category.lower()))
        return res

    # --- MENU PRINCIPAL INTERACTIF (PLEIN ÉCRAN SANS SCROLL & AUTO-ADAPTATIF) ---
    def run_main_hub(self):
        # Scan initial avec spinner animé
        self.run_interactive_scan(first_run=True)

        while True:
            menu_items = [
                ("🔍", *t("menu_1")),
                ("📋", *t("menu_2")),
                ("👁️ ", *t("menu_3")),
                ("🏷️ ", *t("menu_4")),
                ("💾", *t("menu_5")),
                ("🛡️ ", *t("menu_6")),
                ("↩️ ", *t("menu_7")),
                ("📡", *t("menu_8")),
                ("🚪", *t("menu_9"))
            ]

            width = self.get_width()
            height = self.get_height()

            lines_buffer = []

            # 1. Barre supérieure (Ligne 1 absolue)
            lines_buffer.append(self.build_top_bar(width))

            # 2. En-tête / Logo adaptatif selon la hauteur d'écran
            compact_header = (height < 27)
            if compact_header:
                lines_buffer.append(self.center_line(f"{C.CYAN}{C.BOLD}◈  A I   S E C R E T   S C O U T  ◈{C.RESET}  {C.YELLOW}v{VERSION}{C.RESET}", width))
            else:
                lines_buffer.append("")
                for l in ASCII_LOGO:
                    lines_buffer.append(self.center_line(f"{C.CYAN}{C.BOLD}{l}{C.RESET}", width))
                lines_buffer.append(self.center_line(f"{C.YELLOW}{C.BOLD}{t('app_subtitle')}{C.RESET}", width))
                if height >= 32:
                    lines_buffer.append(self.center_line(f"{C.GRAY}Claude Code • Antigravity / Gemini • Codex • GitHub Copilot • Cursor{C.RESET}", width))

            # 3. Dashboard Capsule
            total = len(self.findings)
            crit = sum(1 for f in self.findings if f.severity in ("CRITIQUE", "CRITICAL"))
            high = sum(1 for f in self.findings if f.severity in ("ÉLEVÉ", "HIGH"))
            med = sum(1 for f in self.findings if f.severity in ("MOYEN", "MEDIUM"))

            crit_lbl = t("lbl_crit")
            high_lbl = t("lbl_high")
            med_lbl = t("lbl_med")
            tot_lbl = t("lbl_total_exposed")
            stats_str = f" [ 🔴 {C.BOLD}{crit} {crit_lbl}{C.RESET} │ 🟡 {C.BOLD}{high} {high_lbl}{C.RESET} │ 🔵 {C.BOLD}{med} {med_lbl}{C.RESET} ]  ◈  TOTAL : {C.BOLD}{total} {tot_lbl}{C.RESET} "
            lines_buffer.append(self.center_line(f"{C.BG_DARK}{C.WHITE}{stats_str}{C.RESET}", width))

            if self.active_filter_tool or self.active_filter_project:
                filts = []
                if self.active_filter_tool:
                    filts.append(f"Tool: {self.active_filter_tool}")
                if self.active_filter_project:
                    filts.append(f"Project: {self.active_filter_project}")
                lines_buffer.append(self.center_line(f"{C.MAGENTA}{t('filter_active', filts=', '.join(filts), count=len(self.get_filtered_findings()))}{C.RESET}", width))
            elif height >= 30:
                lines_buffer.append("")

            # 4. Boutons de menu (Responsive : cartes si height >= 42, barres compactes si height < 42)
            card_mode = (height >= 42)
            card_w = min(80, width - 4)
            pad_left = max(0, (width - card_w) // 2)

            for idx, (icon, title, desc) in enumerate(menu_items):
                is_selected = (idx == self.selected_menu_idx)
                
                if card_mode:
                    if is_selected:
                        lines_buffer.append(" " * pad_left + f"{C.CYAN}{C.BOLD}╔" + "═" * (card_w - 2) + "╗" + C.RESET)
                        btn_text = f"  ▶  [{idx + 1}]  {icon}   {title}"
                        sp = max(0, card_w - 2 - display_len(btn_text))
                        lines_buffer.append(" " * pad_left + f"{C.CYAN}{C.BOLD}║{C.BG_BLUE}{C.WHITE}{C.BOLD}{btn_text}{' ' * sp}{C.RESET}{C.CYAN}{C.BOLD}║{C.RESET}")
                        lines_buffer.append(" " * pad_left + f"{C.CYAN}{C.BOLD}╚" + "═" * (card_w - 2) + "╝" + C.RESET)
                    else:
                        btn_text = f"     [{idx + 1}]  {icon}   {title}"
                        sp = max(0, card_w - 2 - display_len(btn_text))
                        lines_buffer.append(" " * pad_left + f"{C.GRAY}┌" + "─" * (card_w - 2) + "┐" + C.RESET)
                        lines_buffer.append(" " * pad_left + f"{C.GRAY}│{C.WHITE}{btn_text}{' ' * sp}{C.RESET}{C.GRAY}│{C.RESET}")
                        lines_buffer.append(" " * pad_left + f"{C.GRAY}└" + "─" * (card_w - 2) + "┘" + C.RESET)
                else:
                    if is_selected:
                        btn_text = f"  ▶  [{idx + 1}]  {icon}   {title}"
                        sp = max(0, card_w - 2 - display_len(btn_text))
                        lines_buffer.append(" " * pad_left + f"{C.CYAN}{C.BOLD}║{C.BG_BLUE}{C.WHITE}{C.BOLD}{btn_text}{' ' * sp}{C.RESET}{C.CYAN}{C.BOLD}║{C.RESET}")
                    else:
                        btn_text = f"     [{idx + 1}]  {icon}   {title}"
                        sp = max(0, card_w - 2 - display_len(btn_text))
                        lines_buffer.append(" " * pad_left + f"{C.GRAY}│{C.WHITE}{btn_text}{' ' * sp}{C.RESET}{C.GRAY}│{C.RESET}")

            # Boîtier de description de l'action sélectionnée
            _, _, curr_desc = menu_items[self.selected_menu_idx]
            if height >= 30:
                box_w = min(card_w, width - 4)
                box_pad = max(0, (width - box_w) // 2)
                lines_buffer.append("")
                act_title = t("action_selected")
                lines_buffer.append(" " * box_pad + f"{C.CYAN}╭─ {C.BOLD}{act_title}{C.RESET}{C.CYAN} " + "─" * max(0, box_w - len(act_title) - 6) + "╮" + C.RESET)
                desc_txt = f"  💡  {curr_desc}"
                sp = max(0, box_w - 2 - display_len(desc_txt))
                lines_buffer.append(" " * box_pad + f"{C.CYAN}│{C.RESET}{C.YELLOW}{desc_txt}{' ' * sp}{C.RESET}{C.CYAN}│{C.RESET}")
                lines_buffer.append(" " * box_pad + f"{C.CYAN}╰" + "─" * (box_w - 2) + "╯" + C.RESET)
            else:
                lines_buffer.append(self.center_line(f"{C.YELLOW}💡 {curr_desc}{C.RESET}", width))

            # 5. Remplir avec des lignes vides jusqu'à l'avant-dernière ligne
            while len(lines_buffer) < height - 1:
                lines_buffer.append("")

            # 6. Barre inférieure (Dernière ligne absolue)
            lines_buffer = lines_buffer[:height - 1]
            lang_indicator = get_lang().upper()
            lines_buffer.append(self.build_bottom_bar(width, t("bottom_nav_hub", lang=lang_indicator)))

            # Rendu atomique sur l'écran
            sys.stdout.write("\033[H" + "\n".join(lines_buffer))
            sys.stdout.flush()

            # Lecture clavier avec flèches, vim (k/j), ZQSD (z/s), chiffres et L pour la langue
            key = read_key()
            if key in ("UP", "k", "K", "z", "Z"):
                self.selected_menu_idx = (self.selected_menu_idx - 1) % len(menu_items)
            elif key in ("DOWN", "j", "J", "s", "S"):
                self.selected_menu_idx = (self.selected_menu_idx + 1) % len(menu_items)
            elif key in ("ENTER", "RIGHT", "SPACE"):
                if self.execute_menu_action(self.selected_menu_idx):
                    break
            elif key in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
                self.selected_menu_idx = int(key) - 1
                if self.execute_menu_action(self.selected_menu_idx):
                    break
            elif key in ("l", "L"):
                self.toggle_language()
            elif key in ("q", "Q", "CTRL_C"):
                break

    def execute_menu_action(self, idx: int) -> bool:
        if idx == 0:
            self.run_interactive_scan()
        elif idx == 1:
            self.run_interactive_table()
        elif idx == 2:
            self.reveal_mode = not self.reveal_mode
        elif idx == 3:
            self.run_filter_dialog()
        elif idx == 4:
            self.run_export_dialog()
        elif idx == 5:
            self.run_global_redact_dialog()
        elif idx == 6:
            self.run_backups_manager_dialog()
        elif idx == 7:
            self.run_watchdog_screen()
        elif idx == 8:
            return True  # Quitter
        return False


    # --- ANIMATION DE CHARGEMENT & PROGRESSION (SPINNER & BARRE) ---
    def run_interactive_scan(self, first_run: bool = False):
        width = self.get_width()
        height = self.get_height()
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

        frame_idx = [0]
        def progress_cb(current, total, step_name):
            frame_idx[0] += 1
            f = SPINNER_FRAMES[frame_idx[0] % len(SPINNER_FRAMES)]
            pct = int((current / total) * 100)
            bar_w = 26
            filled = int(bar_w * current / total)
            pbar = f"{C.GREEN}{'▰' * filled}{C.GRAY}{'▱' * (bar_w - filled)}{C.RESET}"

            lines = []
            lines.append(self.build_top_bar(width))
            if height >= 26:
                lines.append("")
                for l in ASCII_LOGO:
                    lines.append(self.center_line(f"{C.CYAN}{C.BOLD}{l}{C.RESET}", width))
                lines.append("")
            else:
                lines.append(self.center_line(f"{C.CYAN}{C.BOLD}◈  A I   S E C R E T   S C O U T  ◈{C.RESET}", width))

            lines.append(self.center_line(f"{C.YELLOW}{C.BOLD}{t('scan_in_progress')}{C.RESET}", width))
            lines.append("")

            # Boîtier de chargement centré
            box_w = min(68, width - 4)
            pad_left = max(0, (width - box_w) // 2)
            lines.append(" " * pad_left + f"{C.CYAN}╭" + "─" * (box_w - 2) + "╮" + C.RESET)
            loading_line = f"   {C.CYAN}{C.BOLD}{f}{C.RESET}  [{pbar}]  {C.YELLOW}{C.BOLD}{pct:>3}%{C.RESET}"
            sp = max(0, box_w - 2 - display_len(loading_line))
            lines.append(" " * pad_left + f"{C.CYAN}│{C.RESET}{loading_line}{' ' * sp}{C.CYAN}│{C.RESET}")

            disp_step, _ = get_rule_display(step_name)
            status_line = f"   {C.WHITE}{disp_step[:box_w - 8]}{C.RESET}"
            sp2 = max(0, box_w - 2 - display_len(status_line))
            lines.append(" " * pad_left + f"{C.CYAN}│{C.RESET}{status_line}{' ' * sp2}{C.CYAN}│{C.RESET}")
            lines.append(" " * pad_left + f"{C.CYAN}╰" + "─" * (box_w - 2) + "╯" + C.RESET)

            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, t("scan_wait")))

            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()
            time.sleep(0.04)

        self.findings = self.engine.scan(progress_callback=progress_cb)

        if not first_run:
            # Affichage de confirmation avec checkmark
            lines = []
            lines.append(self.build_top_bar(width))
            if height >= 26:
                lines.append("")
                for l in ASCII_LOGO:
                    lines.append(self.center_line(f"{C.CYAN}{C.BOLD}{l}{C.RESET}", width))
                lines.append("")
            else:
                lines.append(self.center_line(f"{C.CYAN}{C.BOLD}◈  A I   S E C R E T   S C O U T  ◈{C.RESET}", width))

            lines.append(self.center_line(f"{C.GREEN}{C.BOLD}{t('scan_done_title')}{C.RESET}", width))
            lines.append(self.center_line(f"{C.WHITE}{t('scan_done_sub', count=len(self.findings))}{C.RESET}", width))
            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, t("scan_return_hint")))
            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()
            while read_key() not in ("ENTER", "SPACE", "ESC"):
                pass

    # --- TABLEAU INTERACTIF DES SECRETS (TUI TABLE) ---
    def run_interactive_table(self):
        while True:
            width = self.get_width()
            height = self.get_height()
            items = self.get_filtered_findings()

            sort_labels = {"severity": t("sort_sev"), "date": t("sort_date"), "tool": t("sort_tool")}
            sort_name = sort_labels.get(self.sort_mode, t("sort_sev"))

            if not items:
                lines = []
                lines.append(self.build_top_bar(width))
                lines.append("")
                if self.search_query:
                    lines.append(self.center_line(f"{C.YELLOW}{t('search_no_match', q=self.search_query)}{C.RESET}", width))
                    lines.append("")
                    lines.append(self.center_line(f"{C.CYAN}{t('search_reset_hint')}{C.RESET}", width))
                else:
                    lines.append(self.center_line(f"{C.YELLOW}{t('filter_no_match')}{C.RESET}", width))
                while len(lines) < height - 1:
                    lines.append("")
                lines = lines[:height - 1]
                hint = "[Backspace/Esc] Clear search │ [Q] Back" if self.search_query else "[Esc] / [Q] Return to dashboard"
                lines.append(self.build_bottom_bar(width, hint))
                sys.stdout.write("\033[H" + "\n".join(lines))
                sys.stdout.flush()
                k = read_key()
                if k in ("BACKSPACE", "ESC") and self.search_query:
                    self.search_query = ""
                    self.selected_table_idx = 0
                    continue
                elif k in ("ENTER", "ESC", "q", "Q"):
                    return

            if self.selected_table_idx >= len(items):
                self.selected_table_idx = len(items) - 1

            max_rows = max(5, height - 11)
            start_row = max(0, min(self.selected_table_idx - max_rows // 2, len(items) - max_rows))
            visible_items = items[start_row : start_row + max_rows]

            lines = []
            lines.append(self.build_top_bar(width))
            lines.append("")

            curr_mode = t("mode_revealed") if self.reveal_mode else t("mode_masked")
            title_str = t("explorer_title", curr=self.selected_table_idx + 1, total=len(items), mode=curr_mode, sort=sort_name)
            lines.append(self.center_line(title_str, width))

            if self.search_query:
                search_badge = t("search_active", q=self.search_query, count=len(items))
                lines.append(self.center_line(f"{C.BG_BLUE}{C.WHITE}{C.BOLD}{search_badge}{C.RESET}", width))
            else:
                lines.append("")

            col_w_idx = 4
            col_w_sev = 11
            col_w_cat = 28
            col_w_tool = 18
            col_w_proj = 22
            col_w_sec = max(20, width - (col_w_idx + col_w_sev + col_w_cat + col_w_tool + col_w_proj + 18))

            header_str = f" {'#':<{col_w_idx}} │ {t('col_severity'):<{col_w_sev}} │ {t('col_category'):<{col_w_cat}} │ {t('col_tool'):<{col_w_tool}} │ {t('col_project'):<{col_w_proj}} │ {t('col_secret'):<{col_w_sec}}"
            lines.append(f"{C.CYAN}{header_str}{C.RESET}")
            lines.append(f"{C.CYAN}{'─' * len(header_str)}{C.RESET}")

            for row_offset, item in enumerate(visible_items):
                actual_idx = start_row + row_offset
                is_selected = (actual_idx == self.selected_table_idx)

                sev_icon = "🔴" if item.severity in ("CRITIQUE", "CRITICAL") else ("🟡" if item.severity in ("ÉLEVÉ", "HIGH") else "🔵")
                sev_str = f"{sev_icon} {item.display_severity()[:8]}"
                cat_str = item.display_category()[:col_w_cat - 2]
                tool_str = item.tool[:col_w_tool - 2]
                proj_str = item.project
                if len(proj_str) > col_w_proj - 2:
                    proj_str = "..." + proj_str[-(col_w_proj - 5):]

                val_str = item.secret_raw if self.reveal_mode else item.secret_masked
                if len(val_str) > col_w_sec - 2:
                    val_str = val_str[:col_w_sec - 5] + "..."

                line = f" {actual_idx + 1:<{col_w_idx}} │ {sev_str:<{col_w_sev}} │ {cat_str:<{col_w_cat}} │ {tool_str:<{col_w_tool}} │ {proj_str:<{col_w_proj}} │ {val_str:<{col_w_sec}}"

                if is_selected:
                    lines.append(f"{C.BG_BLUE}{C.WHITE}{C.BOLD}{line}{C.RESET}")
                else:
                    lines.append(line)

            lines.append(f"{C.CYAN}{'─' * len(header_str)}{C.RESET}")

            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, t("bottom_nav_table")))

            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()

            key = read_key()
            if key in ("UP", "k", "K"):
                self.selected_table_idx = max(0, self.selected_table_idx - 1)
            elif key in ("DOWN", "j", "J"):
                self.selected_table_idx = min(len(items) - 1, self.selected_table_idx + 1)
            elif key == "PAGE_UP":
                self.selected_table_idx = max(0, self.selected_table_idx - max_rows)
            elif key == "PAGE_DOWN":
                self.selected_table_idx = min(len(items) - 1, self.selected_table_idx + max_rows)
            elif key in ("ENTER", "RIGHT", "SPACE"):
                self.show_detail_card(items[self.selected_table_idx])
            elif key in ("r", "R"):
                self.reveal_mode = not self.reveal_mode
            elif key in ("c", "C"):
                self.confirm_and_redact(items[self.selected_table_idx])
            elif key == "/":
                res = self.prompt_input(t("search_prompt"), initial=self.search_query)
                if res is not None:
                    self.search_query = res.strip()
                    self.selected_table_idx = 0
            elif key in ("s", "S"):
                self.sort_mode = "severity"
                self.selected_table_idx = 0
            elif key in ("d", "D"):
                self.sort_mode = "date"
                self.selected_table_idx = 0
            elif key in ("o", "O"):
                self.sort_mode = "tool"
                self.selected_table_idx = 0
            elif key == "BACKSPACE" and self.search_query:
                self.search_query = ""
                self.selected_table_idx = 0
            elif key in ("q", "Q"):
                break
            elif key == "ESC":
                if self.search_query:
                    self.search_query = ""
                    self.selected_table_idx = 0
                else:
                    break

    # --- FICHE DÉTAILLÉE MODALE ---
    def show_detail_card(self, item: Finding):
        while True:
            width = self.get_width()
            height = self.get_height()
            card_w = min(84, width - 4)
            pad_left = max(0, (width - card_w) // 2)

            is_crit = item.severity in ("CRITIQUE", "CRITICAL")
            is_high = item.severity in ("ÉLEVÉ", "HIGH")
            sev_color = C.RED if is_crit else (C.YELLOW if is_high else C.BLUE)

            lines = []
            lines.append(self.build_top_bar(width))
            lines.append("")

            lines.append(" " * pad_left + f"{C.CYAN}╭" + "─" * (card_w - 2) + "╮" + C.RESET)
            card_hdr = f"  {t('card_title')}"
            sp_hdr = max(0, card_w - 2 - display_len(card_hdr))
            lines.append(" " * pad_left + f"{C.CYAN}│{C.BOLD}{C.WHITE}{card_hdr}{' ' * sp_hdr}{C.CYAN}│{C.RESET}")
            lines.append(" " * pad_left + f"{C.CYAN}├" + "─" * (card_w - 2) + "┤" + C.RESET)

            def add_card_line(label, val, color=""):
                txt = f"  {C.BOLD}{label:<16}:{C.RESET} {color}{val}{C.RESET}"
                vis = display_len(txt)
                sp = max(0, card_w - 2 - vis)
                lines.append(" " * pad_left + f"{C.CYAN}│{C.RESET}{txt}{' ' * sp}{C.CYAN}│{C.RESET}")

            add_card_line(t("card_cat"), item.display_category())
            add_card_line(t("card_sev"), item.display_severity(), sev_color + C.BOLD)
            add_card_line(t("card_tool"), item.tool, C.CYAN)
            add_card_line(t("card_proj"), item.project, C.YELLOW)
            add_card_line(t("card_date"), item.timestamp)
            add_card_line(t("card_loc"), f"{Path(item.file_path).name}:{item.line_no}")
            add_card_line(t("card_ctx"), item.display_usage_context(), C.MAGENTA)

            lines.append(" " * pad_left + f"{C.CYAN}├" + "─" * (card_w - 2) + "┤" + C.RESET)
            add_card_line(t("card_plain_val"), item.secret_raw, C.RED + C.BOLD)
            lines.append(" " * pad_left + f"{C.CYAN}├" + "─" * (card_w - 2) + "┤" + C.RESET)

            snip = item.snippet.replace("\n", " ")
            max_snip_w = card_w - 6
            snip_lines = [snip[i:i+max_snip_w] for i in range(0, min(len(snip), max_snip_w * 2), max_snip_w)]
            add_card_line(t("card_log"), snip_lines[0] if snip_lines else "", C.DIM)
            if len(snip_lines) > 1:
                add_card_line("", snip_lines[1], C.DIM)

            lines.append(" " * pad_left + f"{C.CYAN}├" + "─" * (card_w - 2) + "┤" + C.RESET)
            add_card_line(t("card_action_label"), t("card_action_1"), C.WHITE)
            add_card_line("", t("card_action_2"), C.WHITE)
            lines.append(" " * pad_left + f"{C.CYAN}╰" + "─" * (card_w - 2) + "╯" + C.RESET)

            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, t("card_bottom")))

            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()

            key = read_key()
            if key in ("c", "C"):
                self.confirm_and_redact(item)
                break
            elif key in ("q", "Q", "ESC", "ENTER"):
                break

    def confirm_and_redact(self, item: Finding):
        width = self.get_width()
        height = self.get_height()

        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{C.RED}{C.BOLD}{t('confirm_redact_title')}{C.RESET}", width))
        lines.append("")
        lines.append(self.center_line(f"File   : {item.file_path}", width))
        lines.append(self.center_line(f"Line   : {item.line_no}", width))
        lines.append(self.center_line(f"{C.YELLOW}{t('confirm_redact_replace')}{C.RESET}", width))
        lines.append(self.center_line(f"{C.GREEN}{t('confirm_redact_bak')}{C.RESET}", width))
        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, t("confirm_redact_bottom")))

        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()

        key = read_key()
        if key in ("o", "O", "y", "Y"):
            if self.engine.redact_secret(item):
                item.secret_raw = "[REDACTED_BY_AISCOUT]"
                item.secret_masked = "[REDACTED]"
                lines = []
                lines.append(self.build_top_bar(width))
                lines.append("")
                lines.append(self.center_line(f"{C.GREEN}{C.BOLD}{t('redact_success')}{C.RESET}", width))
                lines.append(self.center_line(f"{C.WHITE}{t('redact_file_cleaned', file=Path(item.file_path).name)}{C.RESET}", width))
                lines.append(self.center_line(f"{C.CYAN}{t('redact_bak_created', bak=Path(item.file_path).name + '.bak')}{C.RESET}", width))
                while len(lines) < height - 1:
                    lines.append("")
                lines = lines[:height - 1]
                lines.append(self.build_bottom_bar(width, "[Enter] / [Space] to continue"))
                sys.stdout.write("\033[H" + "\n".join(lines))
                sys.stdout.flush()
                while read_key() not in ("ENTER", "ESC", "SPACE"):
                    pass

    # --- DIALOGUE DE FILTRAGE ---
    def run_filter_dialog(self):
        tools = sorted(list(set(f.tool for f in self.findings)))
        width = self.get_width()
        height = self.get_height()

        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{C.MAGENTA}{C.BOLD}🏷️  GESTION DES FILTRES PAR OUTIL IA{C.RESET}", width))
        lines.append("")

        for i, t in enumerate(tools, 1):
            act = f"{C.GREEN}(ACTIF){C.RESET}" if self.active_filter_tool == t else ""
            lines.append(f"    [{i}] {t} {act}")

        lines.append("")
        lines.append("    [R] Réinitialiser tous les filtres")
        lines.append("    [Q] Retour au menu principal")

        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, "Sélectionnez un numéro [1-N], [R] pour réinitialiser ou [Q] pour retour"))

        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()

        key = read_key()
        if key in ("r", "R"):
            self.active_filter_tool = None
            self.active_filter_project = None
        elif key.isdigit() and 1 <= int(key) <= len(tools):
            self.active_filter_tool = tools[int(key) - 1]

    # --- DIALOGUE D'EXPORTATION ---
    def run_export_dialog(self):
        width = self.get_width()
        height = self.get_height()
        items = self.get_filtered_findings()

        tag = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_dest = self.engine.home / f"audit_secrets_ia_{tag}.md"
        json_dest = self.engine.home / f"audit_secrets_ia_{tag}.json"

        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{C.BLUE}{C.BOLD}💾 EXPORTER LE DOSSIER D'AUDIT COMPLET{C.RESET}", width))
        lines.append("")
        lines.append(f"    [1] Exporter en Markdown : {C.CYAN}{md_dest.name}{C.RESET}")
        lines.append(f"    [2] Exporter en JSON     : {C.CYAN}{json_dest.name}{C.RESET}")
        lines.append("    [Q] Annuler et revenir au menu")

        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, "Appuyez sur [1] ou [2] pour exporter, ou [Q] pour annuler"))

        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()

        key = read_key()
        if key in ("1", "2"):
            # Animation du spinner d'exportation
            for f in SPINNER_FRAMES[:5]:
                anim_lines = []
                anim_lines.append(self.build_top_bar(width))
                anim_lines.append("")
                anim_lines.append(self.center_line(f"{C.CYAN}{C.BOLD}{f} Génération du dossier d'audit en cours...{C.RESET}", width))
                while len(anim_lines) < height - 1:
                    anim_lines.append("")
                anim_lines = anim_lines[:height - 1]
                anim_lines.append(self.build_bottom_bar(width, "Écriture des données sécurisées..."))
                sys.stdout.write("\033[H" + "\n".join(anim_lines))
                sys.stdout.flush()
                time.sleep(0.05)

            target = md_dest if key == "1" else json_dest
            if key == "1":
                self.export_markdown(md_dest, items)
            elif key == "2":
                self.export_json(json_dest, items)

            lines = []
            lines.append(self.build_top_bar(width))
            lines.append("")
            lines.append(self.center_line(f"{C.GREEN}{C.BOLD}✔ RAPPORT D'AUDIT EXPORTÉ AVEC SUCCÈS !{C.RESET}", width))
            lines.append(self.center_line(f"{C.WHITE}Fichier : {C.CYAN}{target}{C.RESET}", width))
            lines.append(self.center_line(f"{C.YELLOW}Total de secrets consignés : {len(items)}{C.RESET}", width))
            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, "[Entrée] ou [Espace] pour revenir au menu"))
            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()
            while read_key() not in ("ENTER", "SPACE", "ESC"):
                pass

    def export_markdown(self, path: Path, items: List[Finding]):
        is_fr = (get_lang() == "fr")
        user_name = os.getenv("USER") or os.getenv("USERNAME") or "user"
        with open(path, "w", encoding="utf-8") as f:
            if is_fr:
                f.write(f"# Rapport d'Audit de Sécurité — Transcriptions d'IA\n\n")
                f.write(f"- **Généré le** : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"- **Utilisateur** : `{user_name}`\n")
                f.write(f"- **Total secrets identifiés** : {len(items)}\n\n")
                f.write("## Synthèse par Niveau de Sévérité\n\n")
                f.write(f"- **Critique** : {sum(1 for x in items if x.severity in ('CRITIQUE', 'CRITICAL'))}\n")
                f.write(f"- **Élevé** : {sum(1 for x in items if x.severity in ('ÉLEVÉ', 'HIGH'))}\n")
                f.write(f"- **Moyen** : {sum(1 for x in items if x.severity in ('MOYEN', 'MEDIUM'))}\n\n")
                f.write("## Détail des Secrets Détectés\n\n")
                f.write("| # | Sévérité | Catégorie | Outil IA | Projet d'Origine | Valeur (Masquée) | Fichier |\n")
                f.write("|---|---|---|---|---|---|---|\n")
                for idx, item in enumerate(items, 1):
                    f.write(f"| {idx} | {item.display_severity()} | {item.display_category()} | {item.tool} | {item.project} | `{item.secret_masked}` | `{Path(item.file_path).name}:{item.line_no}` |\n")
            else:
                f.write(f"# Security Audit Report — AI Assistant Histories\n\n")
                f.write(f"- **Generated on** : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"- **User** : `{user_name}`\n")
                f.write(f"- **Total exposed secrets** : {len(items)}\n\n")
                f.write("## Summary by Severity Level\n\n")
                f.write(f"- **Critical** : {sum(1 for x in items if x.severity in ('CRITIQUE', 'CRITICAL'))}\n")
                f.write(f"- **High** : {sum(1 for x in items if x.severity in ('ÉLEVÉ', 'HIGH'))}\n")
                f.write(f"- **Medium** : {sum(1 for x in items if x.severity in ('MOYEN', 'MEDIUM'))}\n\n")
                f.write("## Detected Secrets Breakdown\n\n")
                f.write("| # | Severity | Category | AI Tool | Origin Project | Value (Masked) | File |\n")
                f.write("|---|---|---|---|---|---|---|\n")
                for idx, item in enumerate(items, 1):
                    f.write(f"| {idx} | {item.display_severity()} | {item.display_category()} | {item.tool} | {item.project} | `{item.secret_masked}` | `{Path(item.file_path).name}:{item.line_no}` |\n")

    def export_json(self, path: Path, items: List[Finding]):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([item.to_dict() for item in items], f, indent=2, ensure_ascii=False)

    # --- ASSAINISSEMENT GLOBAL AVEC ANIMATION DE CHARGEMENT ---
    def run_global_redact_dialog(self):
        items = self.get_filtered_findings()
        width = self.get_width()
        height = self.get_height()

        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{C.RED}{C.BOLD}{t('global_redact_title')}{C.RESET}", width))
        lines.append("")
        lines.append(self.center_line(t("global_redact_msg1", count=len(items)), width))
        lines.append(self.center_line(t("global_redact_msg2"), width))
        lines.append(self.center_line(f"{C.GREEN}{t('global_redact_msg3')}{C.RESET}", width))

        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, t("global_redact_bottom")))

        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()

        key = read_key()
        if key in ("o", "O", "y", "Y"):
            frame_idx = [0]
            total_items = len(items)
            for i, it in enumerate(items, 1):
                frame_idx[0] += 1
                f = SPINNER_FRAMES[frame_idx[0] % len(SPINNER_FRAMES)]
                pct = int((i / total_items) * 100) if total_items > 0 else 100

                bar_w = 26
                filled = int(bar_w * i / total_items) if total_items > 0 else bar_w
                pbar = f"{C.GREEN}{'▰' * filled}{C.GRAY}{'▱' * (bar_w - filled)}{C.RESET}"

                anim_lines = []
                anim_lines.append(self.build_top_bar(width))
                anim_lines.append("")
                anim_lines.append(self.center_line(f"{C.RED}{C.BOLD}{t('global_redact_progress')}{C.RESET}", width))
                anim_lines.append("")

                box_w = min(68, width - 4)
                pad_left = max(0, (width - box_w) // 2)
                anim_lines.append(" " * pad_left + f"{C.CYAN}╭" + "─" * (box_w - 2) + "╮" + C.RESET)
                loading_line = f"   {C.CYAN}{C.BOLD}{f}{C.RESET}  [{pbar}]  {C.YELLOW}{C.BOLD}{pct:>3}%{C.RESET}"
                sp = max(0, box_w - 2 - display_len(loading_line))
                anim_lines.append(" " * pad_left + f"{C.CYAN}│{C.RESET}{loading_line}{' ' * sp}{C.CYAN}│{C.RESET}")

                status_line = f"   {C.WHITE}Redact : {Path(it.file_path).name}:{it.line_no}{C.RESET}"
                sp2 = max(0, box_w - 2 - display_len(status_line))
                anim_lines.append(" " * pad_left + f"{C.CYAN}│{C.RESET}{status_line}{' ' * sp2}{C.CYAN}│{C.RESET}")
                anim_lines.append(" " * pad_left + f"{C.CYAN}╰" + "─" * (box_w - 2) + "╯" + C.RESET)

                while len(anim_lines) < height - 1:
                    anim_lines.append("")
                anim_lines = anim_lines[:height - 1]
                anim_lines.append(self.build_bottom_bar(width, t("global_redact_wait")))

                sys.stdout.write("\033[H" + "\n".join(anim_lines))
                sys.stdout.flush()
                time.sleep(0.03)

                if self.engine.redact_secret(it):
                    it.secret_raw = "[REDACTED_BY_AISCOUT]"
                    it.secret_masked = "[REDACTED]"

            lines = []
            lines.append(self.build_top_bar(width))
            lines.append("")
            lines.append(self.center_line(f"{C.GREEN}{C.BOLD}{t('global_redact_done')}{C.RESET}", width))
            lines.append(self.center_line(f"{C.WHITE}{t('global_redact_done_sub', count=total_items)}{C.RESET}", width))
            lines.append(self.center_line(f"{C.CYAN}{t('global_redact_done_bak')}{C.RESET}", width))
            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, "[Enter] / [Space] to return to dashboard"))
            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()
            while read_key() not in ("ENTER", "SPACE", "ESC"):
                pass

    # --- GESTIONNAIRE DE SAUVEGARDES ET RESTAURATION (.BAK) ---
    def run_backups_manager_dialog(self):
        selected_bak_idx = 0
        while True:
            width = self.get_width()
            height = self.get_height()
            backups = self.engine.list_backups()

            lines = []
            lines.append(self.build_top_bar(width))
            lines.append("")
            lines.append(self.center_line(f"{C.CYAN}{C.BOLD}{t('backups_title')}{C.RESET}", width))
            lines.append(self.center_line(f"{C.GRAY}{t('backups_desc')}{C.RESET}", width))
            lines.append("")

            if not backups:
                lines.append(self.center_line(f"{C.GREEN}{C.BOLD}{t('backups_none')}{C.RESET}", width))
                lines.append(self.center_line(f"{C.WHITE}{t('backups_none_sub')}{C.RESET}", width))
                while len(lines) < height - 1:
                    lines.append("")
                lines = lines[:height - 1]
                lines.append(self.build_bottom_bar(width, "[Enter] / [Esc] Return to dashboard"))
                sys.stdout.write("\033[H" + "\n".join(lines))
                sys.stdout.flush()
                while read_key() not in ("ENTER", "ESC", "SPACE", "q", "Q"):
                    pass
                return

            if selected_bak_idx >= len(backups):
                selected_bak_idx = len(backups) - 1

            max_rows = max(5, height - 12)
            start_row = max(0, min(selected_bak_idx - max_rows // 2, len(backups) - max_rows))
            visible_backups = backups[start_row : start_row + max_rows]

            col_w_idx = 4
            col_w_name = 32
            col_w_tool = 20
            col_w_size = 10
            col_w_date = max(18, width - (col_w_idx + col_w_name + col_w_tool + col_w_size + 15))

            header_str = f" {'#':<{col_w_idx}} │ {t('col_src'):<{col_w_name}} │ {t('col_tool'):<{col_w_tool}} │ {t('col_size'):<{col_w_size}} │ {t('col_bak_date'):<{col_w_date}}"
            lines.append(f"{C.CYAN}{header_str}{C.RESET}")
            lines.append(f"{C.CYAN}{'─' * len(header_str)}{C.RESET}")

            for row_offset, b_path in enumerate(visible_backups):
                actual_idx = start_row + row_offset
                is_selected = (actual_idx == selected_bak_idx)

                orig_name = b_path.stem
                tool = self.engine.identify_tool(str(b_path))
                try:
                    stat = b_path.stat()
                    size_kb = f"{stat.st_size / 1024:.1f} KB"
                    date_str = datetime.fromtimestamp(stat.st_mtime).strftime("%d/%m/%Y %H:%M:%S")
                except Exception:
                    size_kb = "Unknown"
                    date_str = "Unknown"

                name_disp = orig_name[:col_w_name - 2]
                tool_disp = tool[:col_w_tool - 2]
                size_disp = size_kb[:col_w_size - 2]
                date_disp = date_str[:col_w_date - 2]

                line = f" {actual_idx + 1:<{col_w_idx}} │ {name_disp:<{col_w_name}} │ {tool_disp:<{col_w_tool}} │ {size_disp:<{col_w_size}} │ {date_disp:<{col_w_date}}"
                if is_selected:
                    lines.append(f"{C.BG_BLUE}{C.WHITE}{C.BOLD}{line}{C.RESET}")
                else:
                    lines.append(line)

            lines.append(f"{C.CYAN}{'─' * len(header_str)}{C.RESET}")

            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, t("backups_bottom")))

            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()

            key = read_key()
            if key in ("UP", "k", "K"):
                selected_bak_idx = max(0, selected_bak_idx - 1)
            elif key in ("DOWN", "j", "J"):
                selected_bak_idx = min(len(backups) - 1, selected_bak_idx + 1)
            elif key in ("r", "R"):
                target_bak = backups[selected_bak_idx]
                if self.confirm_action(f"Restore {target_bak.stem} from backup copy?"):
                    if self.engine.restore_backup(target_bak):
                        self.show_flash_message(f"✔ {target_bak.stem} restored successfully!", C.GREEN)
                    else:
                        self.show_flash_message("❌ Restoration failed.", C.RED)
            elif key in ("a", "A"):
                if self.confirm_action(f"Restore all {len(backups)} backup files?"):
                    cnt = self.engine.restore_all_backups()
                    self.show_flash_message(f"✔ {cnt} file(s) restored successfully!", C.GREEN)
            elif key in ("p", "P"):
                if self.confirm_action(f"⚠️ PERMANENTLY PURGE all {len(backups)} backup (.bak) files?"):
                    cnt = self.engine.clean_backups()
                    self.show_flash_message(f"✔ {cnt} .bak file(s) permanently deleted.", C.GREEN)
            elif key in ("q", "Q", "ESC"):
                break

    # --- SURVEILLANCE EN TEMPS RÉEL (WATCHDOG DÉDIÉ) ---
    def run_watchdog_screen(self):
        targets = self.engine.get_target_directories()
        known_mtimes: Dict[str, float] = {}

        # Scan initial des mtimes des fichiers surveillés
        for t in targets:
            if t.is_file():
                try:
                    known_mtimes[str(t)] = t.stat().st_mtime
                except Exception:
                    pass
            elif t.is_dir():
                for root, _, files in os.walk(t):
                    for f in files:
                        if not f.endswith((".bak", ".backup")):
                            fp = Path(root) / f
                            try:
                                known_mtimes[str(fp)] = fp.stat().st_mtime
                            except Exception:
                                pass

        events_log: List[str] = [
            f"{C.GRAY}[{datetime.now().strftime('%H:%M:%S')}] {t('watchdog_started', files=len(known_mtimes))}{C.RESET}"
        ]
        alerts_count = 0
        scans_count = 0
        pulse = False

        if not IS_WINDOWS:
            fd = sys.stdin.fileno()
            old_term = termios.tcgetattr(fd)
            tty.setraw(fd)

        try:
            while True:
                pulse = not pulse
                width = self.get_width()
                height = self.get_height()

                lines = []
                lines.append(self.build_top_bar(width))
                lines.append("")

                # Bannière Watchdog avec pulsation visuelle
                indicator = f"{C.GREEN}{t('watchdog_active')}{C.RESET}" if pulse else f"{C.CYAN}{t('watchdog_scanning')}{C.RESET}"
                title_str = f"{t('watchdog_title')}  │  {indicator}"
                lines.append(self.center_line(f"{C.BOLD}{title_str}", width))
                lines.append(self.center_line(f"{C.GRAY}{t('watchdog_desc')}{C.RESET}", width))
                lines.append("")

                # Dashboard statistiques du watchdog
                dash_box = min(80, width - 4)
                dash_pad = max(0, (width - dash_box) // 2)
                stat_str = t("watchdog_stats", files=f"{C.BOLD}{len(known_mtimes)}{C.RESET}", scans=f"{C.BOLD}{scans_count}{C.RESET}", alerts=f"{C.RED + C.BOLD if alerts_count > 0 else C.GREEN + C.BOLD}{alerts_count}{C.RESET}")
                lines.append(" " * dash_pad + f"{C.CYAN}╭" + "─" * (dash_box - 2) + "╮" + C.RESET)
                sp_dash = max(0, dash_box - 2 - display_len(stat_str))
                lines.append(" " * dash_pad + f"{C.CYAN}│{C.RESET}{stat_str}{' ' * sp_dash}{C.CYAN}│{C.RESET}")
                lines.append(" " * dash_pad + f"{C.CYAN}╰" + "─" * (dash_box - 2) + "╯" + C.RESET)
                lines.append("")

                # Journal des événements récents
                log_box_w = min(84, width - 4)
                log_pad = max(0, (width - log_box_w) // 2)
                log_header = t("watchdog_log_title", count=len(events_log))
                dash_r = max(0, log_box_w - 2 - display_len(log_header) - 3)
                lines.append(" " * log_pad + f"{C.CYAN}╭─{C.BOLD}{log_header}{C.RESET}{C.CYAN}" + "─" * dash_r + "╮" + C.RESET)

                avail_log_lines = max(4, height - len(lines) - 4)
                visible_logs = events_log[-avail_log_lines:]

                for log_line in visible_logs:
                    vis_len = display_len(log_line)
                    sp = max(0, log_box_w - 4 - vis_len)
                    lines.append(" " * log_pad + f"{C.CYAN}│{C.RESET}  {log_line}{' ' * sp}{C.CYAN}│{C.RESET}")

                while len(visible_logs) < avail_log_lines:
                    visible_logs.append("")
                    lines.append(" " * log_pad + f"{C.CYAN}│{' ' * (log_box_w - 2)}│{C.RESET}")

                lines.append(" " * log_pad + f"{C.CYAN}╰" + "─" * (log_box_w - 2) + "╯" + C.RESET)

                while len(lines) < height - 1:
                    lines.append("")
                lines = lines[:height - 1]
                lines.append(self.build_bottom_bar(width, t("watchdog_bottom")))

                sys.stdout.write("\033[H" + "\n".join(lines))
                sys.stdout.flush()

                # Attente non-bloquante d'une frappe clavier (1.0 seconde)
                interrupted = False
                if IS_WINDOWS:
                    for _ in range(10):
                        if msvcrt.kbhit():
                            ch = msvcrt.getwch()
                            if ch in ("q", "Q", "\x1b", "\x03"):
                                interrupted = True
                                break
                        time.sleep(0.1)
                else:
                    r, _, _ = select.select([fd], [], [], 1.0)
                    if r:
                        key_bytes = os.read(fd, 32)
                        if key_bytes in (b"q", b"Q", b"\x1b", b"\x03"):
                            interrupted = True
                if interrupted:
                    break

                # Analyse des répertoires pour détecter fichiers nouveaux ou modifiés
                current_files = []
                for t in targets:
                    if t.is_file():
                        current_files.append(t)
                    elif t.is_dir():
                        for root, _, files in os.walk(t):
                            for f in files:
                                if not f.endswith((".bak", ".backup")):
                                    current_files.append(Path(root) / f)

                now_ts = datetime.now().strftime("%H:%M:%S")
                for cp in current_files:
                    sp = str(cp)
                    try:
                        mtime = cp.stat().st_mtime
                    except Exception:
                        continue

                    # Nouveau fichier ou modification détectée
                    if sp not in known_mtimes or mtime > known_mtimes[sp]:
                        is_new = (sp not in known_mtimes)
                        known_mtimes[sp] = mtime
                        scans_count += 1

                        new_findings = self.engine.scan_single_file(cp)
                        if new_findings:
                            alerts_count += len(new_findings)
                            for f in new_findings:
                                alert_msg = t("watchdog_alert_log", cat=f.display_category(), sev=f.display_severity(), tool=f.tool, proj=f.project)
                                events_log.append(f"{C.RED}{C.BOLD}[{now_ts}] {alert_msg}{C.RESET}")
                                notif_title = f"{t('notif_title')} — {f.tool}"
                                notif_body = f"{t('card_cat')}: {f.display_category()}\n{t('card_proj')}: {f.project}\n{t('notif_sec')}: {f.secret_masked}"
                                send_desktop_notification(
                                    title=notif_title,
                                    message=notif_body,
                                    severity=f.severity
                                )
                                sys.stdout.write("\a")
                                sys.stdout.flush()
                                self.findings.append(f)
                        else:
                            action_name = t("watchdog_act_creation") if is_new else t("watchdog_act_modification")
                            events_log.append(f"{C.GRAY}[{now_ts}] {t('watchdog_clean_log', act=action_name, file=cp.name)}{C.RESET}")

                if len(events_log) > 50:
                    events_log = events_log[-50:]

        finally:
            if not IS_WINDOWS:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_term)


# --- POINT D'ENTRÉE ---
def main():
    # Détection précoce du paramètre --lang / -l pour adapter le message d'aide argparse
    for idx, a in enumerate(sys.argv[:-1]):
        if a in ("--lang", "-l"):
            set_lang(sys.argv[idx + 1])
            break

    parser = argparse.ArgumentParser(
        description=t("cli_desc"),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--scan", action="store_true", help=t("cli_help_scan"))
    parser.add_argument("--watch", action="store_true", help=t("cli_help_watch"))
    parser.add_argument("--restore", action="store_true", help=t("cli_help_restore"))
    parser.add_argument("--clean-backups", action="store_true", help=t("cli_help_clean"))
    parser.add_argument("--list-rules", action="store_true", help=t("cli_help_rules"))
    parser.add_argument("--reveal", action="store_true", help=t("cli_help_reveal"))
    parser.add_argument("--json", action="store_true", help=t("cli_help_json"))
    parser.add_argument("--export", type=str, metavar="FILE", help=t("cli_help_export"))
    parser.add_argument("--home-dir", type=str, metavar="DIR", help=t("cli_help_homedir"))
    parser.add_argument("--lang", "-l", type=str, choices=["en", "fr"], help="Force language (en: English, fr: French)")

    args = parser.parse_args()
    if args.lang:
        set_lang(args.lang)

    user_home = Path(args.home_dir) if args.home_dir else None
    engine = ScoutEngine(user_home=user_home)

    if args.list_rules:
        print(f"\n{C.CYAN}{C.BOLD}◈  AI SECRET SCOUT — {t('cli_rules_title')} ({len(engine.patterns)})  ◈{C.RESET}\n")
        print(f" {'#':<3} │ {t('col_severity'):<10} │ {t('cli_rule_name'):<35} │ {t('cli_rule_desc'):<45}")
        print(f"─" * 98)
        for i, (name, conf) in enumerate(engine.patterns.items(), 1):
            rule_disp, rule_desc = get_rule_display(name, conf.get("description", ""))
            sev_str = fmt_severity(conf.get("severity", "MOYEN"))
            print(f" {i:<3} │ {sev_str:<10} │ {rule_disp[:33]:<35} │ {rule_desc[:43]:<45}")
        print(f"\n{C.GRAY}{t('cli_user_config', path=str(CUSTOM_RULES_FILE))}{C.RESET}\n")
        return

    if args.restore:
        count = engine.restore_all_backups()
        if count > 0:
            print(f"\n{C.GREEN}{C.BOLD}{t('cli_restore_success', count=count)}{C.RESET}\n")
        else:
            print(f"\n{C.YELLOW}{t('cli_restore_none')}{C.RESET}\n")
        return

    if args.clean_backups:
        count = engine.clean_backups()
        if count > 0:
            print(f"\n{C.GREEN}{C.BOLD}{t('cli_clean_success', count=count)}{C.RESET}\n")
        else:
            print(f"\n{C.YELLOW}{t('cli_clean_none')}{C.RESET}\n")
        return

    if args.watch:
        tui = ScoutTUI(engine)
        try:
            tui.enter_tui()
            tui.run_watchdog_screen()
        except KeyboardInterrupt:
            pass
        finally:
            tui.exit_tui()
            print(f"\n{C.GREEN}{t('cli_watch_stopped')}{C.RESET}\n")
        return

    if args.scan or args.json or args.export:
        findings = engine.scan()
        if args.json:
            print(json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False))
            return
        if args.export:
            p = Path(args.export)
            tui = ScoutTUI(engine)
            if p.suffix.lower() == ".json":
                tui.export_json(p, findings)
            else:
                tui.export_markdown(p, findings)
            print(t('cli_export_success', path=str(p)))
            return
        tui = ScoutTUI(engine)
        tui.findings = findings
        tui.reveal_mode = args.reveal
        tui.run_interactive_table()
        return

    # Lancement du TUI plein écran
    tui = ScoutTUI(engine)
    try:
        tui.enter_tui()
        tui.run_main_hub()
    except KeyboardInterrupt:
        pass
    finally:
        tui.exit_tui()
        print(f"\n{C.GREEN}{t('cli_tui_closed')}{C.RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stderr.close()
        except Exception:
            pass
        sys.exit(0)
