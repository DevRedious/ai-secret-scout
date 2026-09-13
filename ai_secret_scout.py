#!/usr/bin/env python3
"""
===============================================================================
AI SECRET SCOUT (aiscout) — Full TUI Application
Audit & Détection de secrets en clair dans les transcriptions & mémoires d'IA
Interface TUI plein écran avec logo centré, menus larges, flèches et animations
Compatible : Claude Code, Antigravity/Gemini CLI, Codex, Copilot CLI, Cursor, Aider
===============================================================================
"""

import argparse
import contextlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import msvcrt
    # Active les séquences d'échappement VT100 / ANSI sous console Windows
    os.system("")
    with contextlib.suppress(AttributeError, OSError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdin.reconfigure(encoding="utf-8")
else:
    import select
    import termios
    import tty

VERSION = "2.4.8"

# --- INTERNATIONALISATION (I18N) ---
def detect_default_lang() -> str:
    """Détecte la langue système par défaut (FR si locale fr, sinon EN)."""
    env = os.getenv("LC_ALL") or os.getenv("LC_MESSAGES") or os.getenv("LANG") or ""
    return "fr" if "fr" in env.lower() else "en"

CURRENT_LANG = detect_default_lang()

def set_lang(lang: str | None):
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

def fmt_severity(sev: str, lang: str | None = None) -> str:
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

def get_rule_display(name: str, default_desc: str = "", lang: str | None = None) -> tuple[str, str]:
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

def fmt_usage_context(ctx: str, lang: str | None = None) -> str:
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
        "cli_help_version": "Affiche la version installée et quitte",
        "cli_help_update": "« update » : met à jour AI Secret Scout via npm (seul accès réseau, sur demande)",
        "update_checking": "Vérification de la dernière version sur le registre npm...",
        "update_uptodate": "✔ AI Secret Scout est à jour (v{version}).",
        "update_available": "Nouvelle version disponible : v{current} → v{latest}",
        "update_running": "Mise à jour : {cmd}",
        "update_done": "✔ AI Secret Scout mis à jour en v{latest}.",
        "update_failed": "❌ La mise à jour a échoué (code {code}). Droits insuffisants ? Relancez avec les droits d'administration ou configurez un préfixe npm utilisateur.",
        "update_npx": "Lancé via npx : « {cmd} » exécute directement la dernière version.",
        "update_manual": "AI Secret Scout n'est pas installé globalement par npm : lancez « {cmd} » pour installer la dernière version.",
        "update_no_npm": "❌ npm est introuvable : impossible de vérifier ou d'installer une mise à jour.",
        "update_check_failed": "❌ Impossible d'interroger le registre npm : {error}",
        "confirm_title": "⚠️  CONFIRMATION",
        "confirm_bottom": "[O] Confirmer  │  [Annuler] Toute autre touche",
        "continue_hint": "[Entrée] / [Espace] pour continuer",
        "filter_tool_lbl": "Outil",
        "filter_project_lbl": "Projet",
        "table_empty_search_hint": "[Backspace/Esc] Effacer la recherche │ [Q] Retour",
        "table_empty_hint": "[Esc] / [Q] Retour au tableau de bord",
        "redact_file_lbl": "Fichier",
        "redact_line_lbl": "Ligne",
        "filter_title": "🏷️  GESTION DES FILTRES PAR OUTIL IA",
        "filter_reset": "[R] Réinitialiser tous les filtres",
        "filter_back": "[Q] Retour au menu principal",
        "filter_active_tag": "(ACTIF)",
        "filter_bottom": "Sélectionnez un numéro [1-N], [R] pour réinitialiser ou [Q] pour retour",
        "export_title": "💾 EXPORTER LE DOSSIER D'AUDIT COMPLET",
        "export_md": "[1] Exporter en Markdown : {name}",
        "export_json": "[2] Exporter en JSON     : {name}",
        "export_cancel": "[Q] Annuler et revenir au menu",
        "export_bottom": "Appuyez sur [1] ou [2] pour exporter, ou [Q] pour annuler",
        "export_progress": "Génération du dossier d'audit en cours...",
        "export_writing": "Écriture des données sécurisées...",
        "export_done": "✔ RAPPORT D'AUDIT EXPORTÉ AVEC SUCCÈS !",
        "export_file": "Fichier : {path}",
        "export_total": "Total de secrets consignés : {count}",
        "export_return": "[Entrée] ou [Espace] pour revenir au menu",
        "bak_confirm_one": "Restaurer {name} depuis sa sauvegarde ?",
        "bak_restored_one": "✔ {name} restauré avec succès !",
        "bak_restore_failed": "❌ Échec de la restauration.",
        "bak_confirm_all": "Restaurer les {count} sauvegardes ?",
        "bak_restored_all": "✔ {count} fichier(s) restauré(s) avec succès !",
        "bak_confirm_purge": "⚠️ SUPPRIMER DÉFINITIVEMENT les {count} sauvegardes (.bak) ?",
        "bak_purged": "✔ {count} fichier(s) .bak supprimé(s) définitivement.",
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
        "cli_help_version": "Print the installed version and exit",
        "cli_help_update": "\"update\": update AI Secret Scout through npm (only network access, on demand)",
        "update_checking": "Checking the latest version on the npm registry...",
        "update_uptodate": "✔ AI Secret Scout is up to date (v{version}).",
        "update_available": "New version available: v{current} → v{latest}",
        "update_running": "Updating: {cmd}",
        "update_done": "✔ AI Secret Scout updated to v{latest}.",
        "update_failed": "❌ Update failed (code {code}). Missing permissions? Retry with administrator rights or configure a user-level npm prefix.",
        "update_npx": "Launched through npx: \"{cmd}\" runs the latest version directly.",
        "update_manual": "AI Secret Scout is not installed globally with npm: run \"{cmd}\" to install the latest version.",
        "update_no_npm": "❌ npm not found: cannot check for or install an update.",
        "update_check_failed": "❌ Could not query the npm registry: {error}",
        "confirm_title": "⚠️  CONFIRMATION",
        "confirm_bottom": "[Y] Confirm  │  [Cancel] Any other key",
        "continue_hint": "[Enter] / [Space] to continue",
        "filter_tool_lbl": "Tool",
        "filter_project_lbl": "Project",
        "table_empty_search_hint": "[Backspace/Esc] Clear search │ [Q] Back",
        "table_empty_hint": "[Esc] / [Q] Return to dashboard",
        "redact_file_lbl": "File",
        "redact_line_lbl": "Line",
        "filter_title": "🏷️  AI TOOL FILTERS",
        "filter_reset": "[R] Reset all filters",
        "filter_back": "[Q] Back to main menu",
        "filter_active_tag": "(ACTIVE)",
        "filter_bottom": "Pick a number [1-N], [R] to reset or [Q] to go back",
        "export_title": "💾 EXPORT FULL AUDIT REPORT",
        "export_md": "[1] Export as Markdown : {name}",
        "export_json": "[2] Export as JSON     : {name}",
        "export_cancel": "[Q] Cancel and return to menu",
        "export_bottom": "Press [1] or [2] to export, or [Q] to cancel",
        "export_progress": "Generating audit report...",
        "export_writing": "Writing report data...",
        "export_done": "✔ AUDIT REPORT EXPORTED SUCCESSFULLY!",
        "export_file": "File : {path}",
        "export_total": "Secrets recorded : {count}",
        "export_return": "[Enter] or [Space] to return to menu",
        "bak_confirm_one": "Restore {name} from its backup copy?",
        "bak_restored_one": "✔ {name} restored successfully!",
        "bak_restore_failed": "❌ Restoration failed.",
        "bak_confirm_all": "Restore all {count} backup files?",
        "bak_restored_all": "✔ {count} file(s) restored successfully!",
        "bak_confirm_purge": "⚠️ PERMANENTLY PURGE all {count} backup (.bak) files?",
        "bak_purged": "✔ {count} .bak file(s) permanently deleted.",
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
        except (KeyError, IndexError, ValueError):
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
        "regex": r"-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----",
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
        "regex": r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b",
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
        "regex": r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-\.]+:(?!(?:password|root|postgres|admin)@|\$\{|<|\*+@|\[|%|YOUR_)([^\s@\"'`:\\]+)@[a-zA-Z0-9_\-\.]+",
        "severity": "CRITIQUE",
        "description": "Chaîne de connexion de base de données contenant identifiant et mot de passe en clair."
    },
    "Variable d'environnement sensible": {
        "regex": r"(?i)\b(?:PGPASSWORD|MYSQL_PWD|DB_PASSWORD|AUTH_TOKEN|API_KEY|SECRET_KEY|COOLIFY_API_TOKEN)=(?:\\?[\"'])?([A-Za-z0-9_\-@#$%^&+=!]{8,})",
        "severity": "ÉLEVÉ",
        "description": "Affectation de mot de passe ou secret via variable d'environnement dans un terminal."
    },
    "Mot de passe passé en commande CLI": {
        "regex": r"(?i)\b(?:--password[\s=]+|sshpass\s+-p\s*|mysql\s+(?:-[a-zA-Z0-9_]+\s+)*-p)(?:\\?[\"'])?([A-Za-z0-9_\-@#$%^&+=!]{6,})",
        "severity": "MOYEN",
        "description": "Mot de passe transmis directement dans une commande dédiée (ex. sshpass, mysql, --password)."
    },
    "Mot de passe en clair dans le Prompt": {
        "regex": r"(?i)(?:mon mot de passe est|le mot de passe (?:est|c'est)|mdp\s*[:=]|mot de passe\s*[:=]|my password is|the password is|password\s*[:=])\s*(?:\\?[\"'])?([A-Za-z0-9_\-@#$%^&+=!]{6,})",
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

def load_custom_rules() -> dict[str, dict[str, str]]:
    """Charge les règles personnalisées de l'utilisateur depuis rules.json."""
    if not CUSTOM_RULES_FILE.exists():
        with contextlib.suppress(OSError):
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
        return {}

    try:
        with open(CUSTOM_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = {}
        for k, v in data.items():
            if k.startswith("_") or not isinstance(v, dict):
                continue
            if "regex" in v and "severity" in v:
                try:
                    re.compile(v["regex"])
                except (re.error, TypeError):
                    continue  # une regex invalide ne doit pas interrompre tout le scan
                rules[f"{k} [CUSTOM]"] = {
                    "regex": v["regex"],
                    "severity": v.get("severity", "MOYEN"),
                    "description": v.get("description", "Règle personnalisée utilisateur.")
                }
        return rules
    except (OSError, ValueError, AttributeError):
        # Fichier illisible, JSON invalide ou racine qui n'est pas un objet.
        return {}


# Script fixe : le titre et le texte (noms de projet, chemins de session) arrivent par l'environnement.
# Insérés dans la chaîne entre guillemets doubles, un « $(...) » y serait exécuté par PowerShell.
WINDOWS_NOTIFICATION_SCRIPT = (
    '[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms"); '
    '$objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon; '
    '$objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Shield; '
    '$objNotifyIcon.BalloonTipIcon = "Warning"; '
    '$objNotifyIcon.BalloonTipTitle = $env:AISCOUT_BALLOON_TITLE; '
    '$objNotifyIcon.BalloonTipText = $env:AISCOUT_BALLOON_TEXT; '
    '$objNotifyIcon.Visible = $True; '
    '$objNotifyIcon.ShowBalloonTip(5000); '
    'Start-Sleep -Seconds 1; '
    '$objNotifyIcon.Dispose()'
)


def build_windows_notification(title: str, message: str) -> tuple[list[str], dict[str, str]]:
    """Commande PowerShell et environnement d'une notification Windows."""
    env = {**os.environ, "AISCOUT_BALLOON_TITLE": title, "AISCOUT_BALLOON_TEXT": message.replace("\n", " ")}
    return ["powershell", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_NOTIFICATION_SCRIPT], env


def send_desktop_notification(title: str, message: str, severity: str = "normal"):
    """Envoie une notification de bureau native sous Linux / KDE / GNOME ou Windows 10/11."""
    if os.getenv("AISCOUT_NO_NOTIFY"):
        return
    if IS_WINDOWS:
        args, env = build_windows_notification(title, message)
        with contextlib.suppress(OSError):
            subprocess.Popen(
                args,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        return

    if shutil.which("notify-send"):
        urgency = "critical" if severity in ("CRITIQUE", "ÉLEVÉ") else "normal"
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run([
                "notify-send",
                "-u", urgency,
                "-a", "AI Secret Scout",
                "-i", "security-high",
                title,
                message
            ], capture_output=True, timeout=2, check=False)


PLACEHOLDER_KEYWORDS = [
    "your_key", "your_token", "your_password", "your_api_key", "your_secret",
    "example", "placeholder", "dummy", "fake", "xxxx", "00000", "12345",
    "abcdef", "sk-ant-xxx", "ghp_xxx", "undefined", "change_me",
    "changeme", "foobar", "redacted", "token_here", "key_here", "sample", "postgres_db"
]

# Mots courts : pertinents pour un mot de passe tapé à la main, mais qu'un jeton aléatoire
# contient par hasard (« dev » apparaît dans ~0,1 % des PAT GitHub). Ils ne s'appliquent
# donc pas aux règles intégrées à préfixe fixe.
WEAK_PLACEHOLDER_KEYWORDS = [
    "test", "password", "secret", "null", "none", "true", "false", "localhost",
    "admin", "root", "dev", "prod", "ostgres", "postgres"
]

# Sous-chaînes des noms de règles dont la valeur est du texte libre (mot de passe, variable).
FREE_TEXT_RULE_MARKERS = ["Prompt", "CLI", "commande", "sensible", "Base de données"]

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


def local_time(timestamp: float | None = None) -> datetime:
    """Heure locale avec fuseau : maintenant, ou à partir d'un horodatage (mtime)."""
    if timestamp is None:
        return datetime.now(timezone.utc).astimezone()
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone()


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

        return data.decode("utf-8", errors="ignore")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)



class Finding:
    def __init__(self, category: str, secret_raw: str, file_path: str, line_no: int,
                 tool: str, project: str, usage_context: str, snippet: str,
                 timestamp: str | None = None, severity: str | None = None,
                 description: str | None = None):
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

    def display_category(self, lang: str | None = None) -> str:
        name, _ = get_rule_display(self.category, default_desc=self.description, lang=lang)
        return name

    def display_severity(self, lang: str | None = None) -> str:
        return fmt_severity(self.severity, lang=lang)

    def display_usage_context(self, lang: str | None = None) -> str:
        return fmt_usage_context(self.usage_context, lang=lang)

    @staticmethod
    def mask(val: str) -> str:
        s = val.strip().strip("'\"")
        if len(s) <= 8:
            return s[:2] + "****"
        return s[:4] + "*" * (min(len(s) - 8, 20)) + s[-4:]

    def to_dict(self) -> dict[str, Any]:
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
    def __init__(self, user_home: Path | None = None):
        self.home = user_home or Path.home()
        self.rg_path = self._locate_ripgrep()
        self.patterns = dict(PATTERNS)
        self.patterns.update(load_custom_rules())
        self.findings: list[Finding] = []
        self._cwd_cache: dict[str, str] = {}

    def _locate_ripgrep(self) -> str | None:
        if os.getenv("AISCOUT_DISABLE_RIPGREP"):
            return None
        system_rg = shutil.which("rg")
        if system_rg:
            return system_rg
        cargo_rg = self.home / ".cargo" / "bin" / "rg"
        if cargo_rg.exists() and os.access(cargo_rg, os.X_OK):
            return str(cargo_rg)
        return None

    def get_candidate_targets(self) -> list[Path]:
        """Tous les emplacements connus, qu'ils existent ou non."""
        targets = [
            self.home / ".claude" / "projects",
            self.home / ".claude" / "history.jsonl",
            self.home / ".claude" / "handoff",
            self.home / ".gemini" / "antigravity-cli" / "brain",
            self.home / ".gemini" / "antigravity-cli" / "history.jsonl",
            self.home / ".gemini" / "antigravity-ide" / "conversations",
            self.home / ".codex" / "sessions",
            self.home / ".codex" / "history.jsonl",
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
        return targets

    def get_target_directories(self) -> list[Path]:
        return [p for p in self.get_candidate_targets() if p.exists()]

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
            # Fichier illisible, JSON invalide, "cwd" qui n'est pas une chaîne : repli sur le nom du dossier.
            with contextlib.suppress(OSError, ValueError, AttributeError, RecursionError), open(p, encoding="utf-8", errors="ignore") as f:
                for _ in range(10):
                    line = f.readline()
                    if not line:
                        break
                    if '"cwd"' in line:
                        data = json.loads(line)
                        if data.get("cwd"):
                            res = data["cwd"].replace(str(self.home), "~")
                            self._cwd_cache[file_path] = res
                            return res

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

    def determine_usage_context(self, raw_line: str, tool: str) -> tuple[str, str]:
        line_clean = raw_line.strip()
        usage = "Texte consigné en session"
        try:
            data = json.loads(line_clean)
        except (ValueError, RecursionError):
            data = None
        if isinstance(data, dict):
            # Antigravity porte aussi un champ "type" : tester "step_index" en premier.
            if "step_index" in data:
                stype = data.get("type")
                if stype == "USER_INPUT":
                    usage = "Prompt utilisateur Antigravity"
                elif stype == "PLANNER_RESPONSE":
                    usage = "Raisonnement / Réponse du modèle"
            elif data.get("type") == "user":
                msg = data.get("message")
                content = msg.get("content", "") if isinstance(msg, dict) else ""
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "tool_result":
                            usage = "Sortie d'outil exécuté (commande bash, .env ou infisical)"
                            snip = str(item.get("content", ""))[:200]
                            return usage, snip
                usage = "Message / Prompt utilisateur direct"
            elif data.get("type") == "assistant":
                usage = "Réponse / Génération de l'assistant IA"

        if "infisical" in line_clean.lower():
            usage = "Sortie de commande Infisical ou dump de secrets"
        elif "export " in line_clean:
            usage = "Commande bash 'export' d'une variable d'environnement"
        elif "password" in line_clean.lower() or "mot de passe" in line_clean.lower():
            usage = "Transmission d'identifiant dans la conversation"

        snippet = line_clean[:180].replace("\n", " ").replace("\r", "")
        return usage, snippet

    def is_valid_secret(self, text: str, category: str = "", full_line: str = "") -> bool:
        val = text.strip().strip("'\"`")
        lower_t = val.lower()

        if len(val) < 6:
            return False

        if val.startswith(("$", "<", "{{", "[", "(")):
            return False
        if val.endswith((">", "]", ")", "}")):
            return False

        is_free_text = any(kw in category for kw in FREE_TEXT_RULE_MARKERS)
        keywords = PLACEHOLDER_KEYWORDS
        if is_free_text or category not in PATTERNS:
            keywords = PLACEHOLDER_KEYWORDS + WEAK_PLACEHOLDER_KEYWORDS
        for ph in keywords:
            if ph in lower_t:
                return False
        if re.search(r"^(?:YOUR_|VOTRE_|SAMPLE_|MY_|TEST_|EXAMPLE_)[A-Z0-9_]+$", val, re.IGNORECASE):
            return False
        if re.search(r"_[A-Z]+_(?:KEY|TOKEN|SECRET|PASSWORD|HERE)$", val, re.IGNORECASE):
            return False

        if len(set(lower_t)) <= 2 and len(val) >= 6:
            return False

        if any(marker in full_line for marker in ["AI SECRET SCOUT", "[REDACTED_BY_AISCOUT]", "FICHE DÉTAILLÉE DU SECRET", "rapport_audit"]):
            return False

        if "Clé Privée" in category and "END " not in full_line and "PRIVATE KEY" not in full_line.split(text)[-1]:
            return False

        if any(kw in category for kw in ["Prompt", "CLI", "commande", "sensible"]):
            if lower_t in COMMON_WORDS_FR_EN:
                return False

            classes = count_character_classes(val)
            entropy = calculate_entropy(val)

            if classes == 1:
                if val.isalpha():
                    return False
                if entropy < 3.0:
                    return False

            if classes == 2 and val.istitle() and val.isalpha():
                return False

        return True

    @staticmethod
    def rg_compatible_regex(regex: str) -> str:
        """Retire les assertions (?=…) (?!…) (?<=…) (?<!…), que ripgrep refuse.

        Le motif obtenu est plus large que l'original : ripgrep ne fait que présélectionner
        les lignes, et la regex complète est réappliquée en Python par _match_line()."""
        out = []
        i = 0
        while i < len(regex):
            if regex[i] == "\\":
                out.append(regex[i:i + 2])
                i += 2
                continue
            if regex.startswith(("(?=", "(?!", "(?<=", "(?<!"), i):
                depth, j, in_class = 0, i, False
                while j < len(regex):
                    c = regex[j]
                    if c == "\\":
                        j += 2
                        continue
                    if in_class:
                        in_class = c != "]"
                    elif c == "[":
                        in_class = True
                    elif c == "(":
                        depth += 1
                    elif c == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                i = j + 1
                continue
            out.append(regex[i])
            i += 1
        return "".join(out)

    def _file_meta(self, fpath: str) -> tuple[str, str, str]:
        try:
            mtime = local_time(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
        except OSError:
            mtime = "Inconnu"
        return self.identify_tool(fpath), self.resolve_project(fpath), mtime

    def _match_line(self, cat_name: str, conf: dict[str, str], line: str, fpath: str, lno: int,
                    tool: str, project: str, mtime: str) -> list[Finding]:
        """Point unique de correspondance : ripgrep, repli Python et watchdog passent tous ici."""
        if "ai_secret_scout" in fpath or "scan_secrets" in fpath:
            return []
        found = []
        for m in re.finditer(conf["regex"], line):
            raw = m.group(1) if m.groups() and m.group(1) is not None else m.group(0)
            if not self.is_valid_secret(raw, category=cat_name, full_line=line):
                continue
            usage, snippet = self.determine_usage_context(line, tool)
            found.append(Finding(
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
        return found

    def _scan_file(self, fpath: str, patterns: dict[str, dict[str, str]],
                   tool: str, project: str, mtime: str) -> list[Finding]:
        found = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                for lno, line in enumerate(f, 1):
                    for cat_name, conf in patterns.items():
                        found.extend(self._match_line(cat_name, conf, line, fpath, lno, tool, project, mtime))
        except OSError:
            pass
        return found

    @staticmethod
    def _list_scan_files(targets: list[str]) -> list[str]:
        files = []
        for target in targets:
            tp = Path(target)
            if tp.is_file():
                files.append(target)
            elif tp.is_dir():
                for root, _, names in os.walk(tp):
                    for name in names:
                        if name.endswith((".jsonl", ".json", ".md")):
                            files.append(os.path.join(root, name))
        return files

    def _rg_search(self, regex: str, targets: list[str]) -> list[tuple[str, int, str]] | None:
        """Lignes trouvées par ripgrep, ou None si ripgrep refuse la regex."""
        cmd = [self.rg_path, "--null", "-H", "-n", "--no-heading", "--no-messages",
               "--glob", "!*.bak", "--glob", "!*.backup",
               "-e", self.rg_compatible_regex(regex)] + targets
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
        if proc.returncode == 2 and not proc.stdout and "regex" in proc.stderr.lower():
            return None
        results = []
        # --null sépare le chemin par un octet nul : un « : » dans le chemin (C:\ sous Windows)
        # ne décale plus le découpage. split("\n") et non splitlines(), qui coupe aussi sur
        # U+2028 ou \x0c présents dans le contenu.
        for record in proc.stdout.split("\n"):
            fpath, sep, rest = record.partition("\0")
            if not sep:
                continue
            lno_str, _, content = rest.partition(":")
            try:
                lno = int(lno_str)
            except ValueError:
                lno = 0
            results.append((fpath, lno, content.rstrip("\r")))
        return results

    def scan(self, progress_callback=None) -> list[Finding]:
        self.findings = []
        targets = [str(p) for p in self.get_target_directories()]
        if not targets:
            return []

        meta_cache: dict[str, tuple[str, str, str]] = {}

        def meta(fpath: str) -> tuple[str, str, str]:
            if fpath not in meta_cache:
                meta_cache[fpath] = self._file_meta(fpath)
            return meta_cache[fpath]

        python_patterns = dict(self.patterns)
        if self.rg_path:
            python_patterns = {}
            total_cats = len(self.patterns)
            for idx, (cat_name, conf) in enumerate(self.patterns.items(), 1):
                if progress_callback:
                    progress_callback(idx, total_cats, f"Analyse : {cat_name}")
                hits = self._rg_search(conf["regex"], targets)
                if hits is None:
                    python_patterns[cat_name] = conf
                    continue
                for fpath, lno, content in hits:
                    self.findings.extend(self._match_line(cat_name, conf, content, fpath, lno, *meta(fpath)))

        if python_patterns:
            all_files = self._list_scan_files(targets)
            for idx, fpath in enumerate(all_files, 1):
                if progress_callback and idx % 10 == 0:
                    progress_callback(idx, len(all_files), f"Lecture : {Path(fpath).name}")
                self.findings.extend(self._scan_file(fpath, python_patterns, *meta(fpath)))

        dedup_map: dict[tuple[str, str, str, int], Finding] = {}
        for f in self.findings:
            key = (f.category, f.secret_raw, f.file_path, f.line_no)
            if key not in dedup_map:
                dedup_map[key] = f
        self.findings = sorted(dedup_map.values(), key=lambda x: (x.severity != "CRITIQUE", x.severity != "ÉLEVÉ", x.category))
        return self.findings

    def scan_single_file(self, fpath: Path) -> list[Finding]:
        """Analyse unitairement un fichier pour y détecter des secrets."""
        if not fpath.is_file() or str(fpath).endswith((".bak", ".backup")):
            return []
        return self._scan_file(str(fpath), self.patterns, *self._file_meta(str(fpath)))

    def redact_secret(self, finding: Finding) -> bool:
        """Remplace toutes les occurrences du secret. True si le fichier n'en contient plus."""
        target = Path(finding.file_path)
        if not finding.secret_raw or finding.secret_raw == "[REDACTED_BY_AISCOUT]" or not target.is_file():
            return False
        needle = finding.secret_raw.encode("utf-8")
        try:
            # En octets : les séquences non UTF-8 et les fins de ligne restent intactes.
            content = target.read_bytes()
            if needle not in content:
                return True
            backup_file = target.with_name(target.name + ".bak")
            if not backup_file.exists():
                shutil.copy2(target, backup_file)
            target.write_bytes(content.replace(needle, b"[REDACTED_BY_AISCOUT]"))
            return True
        except OSError:
            return False

    def list_backups(self) -> list[Path]:
        """Recherche et liste tous les fichiers de sauvegarde .bak dans les répertoires d'IA."""
        backups = []
        for target in self.get_candidate_targets():
            if target.is_dir():
                for root, _, files in os.walk(target):
                    for f in files:
                        if f.endswith(".bak"):
                            backups.append(Path(root) / f)
            else:
                # Cible fichier (history.jsonl…) : sa sauvegarde est posée à côté.
                bak = target.with_name(target.name + ".bak")
                if bak.is_file():
                    backups.append(bak)
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
        except OSError:
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
            with contextlib.suppress(OSError):
                b.unlink()
                count += 1
        return count


# --- GESTIONNAIRE D'AFFICHAGE PLEIN ÉCRAN (TUI ENGINE) ---
class ScoutTUI:
    def __init__(self, engine: ScoutEngine):
        self.engine = engine
        self.findings: list[Finding] = []
        self.active_filter_tool: str | None = None
        self.active_filter_project: str | None = None
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
        date_str = local_time().strftime("%d/%m/%Y %H:%M")
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

    def prompt_input(self, prompt_label: str, initial: str = "") -> str | None:
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
        lines.append(self.center_line(f"{C.YELLOW}{C.BOLD}{t('confirm_title')}{C.RESET}", width))
        lines.append("")
        lines.append(self.center_line(f"{C.WHITE}{question}{C.RESET}", width))
        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, t("confirm_bottom")))
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
        lines.append(self.build_bottom_bar(width, t("continue_hint")))
        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()
        while read_key() not in ("ENTER", "SPACE", "ESC"):
            pass

    def toggle_language(self):
        new_lang = toggle_lang()
        msg = "Language switched to English (EN)" if new_lang == "en" else "Langue basculée en Français (FR)"
        self.show_flash_message(f"✔ {msg}", C.CYAN)

    def get_filtered_findings(self) -> list[Finding]:
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
                    filts.append(f"{t('filter_tool_lbl')}: {self.active_filter_tool}")
                if self.active_filter_project:
                    filts.append(f"{t('filter_project_lbl')}: {self.active_filter_project}")
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
                hint = t("table_empty_search_hint") if self.search_query else t("table_empty_hint")
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

            def add_card_line(label, val, color="", lines=lines, pad_left=pad_left, card_w=card_w):
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
        lines.append(self.center_line(f"{t('redact_file_lbl'):<7}: {item.file_path}", width))
        lines.append(self.center_line(f"{t('redact_line_lbl'):<7}: {item.line_no}", width))
        lines.append(self.center_line(f"{C.YELLOW}{t('confirm_redact_replace')}{C.RESET}", width))
        lines.append(self.center_line(f"{C.GREEN}{t('confirm_redact_bak')}{C.RESET}", width))
        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, t("confirm_redact_bottom")))

        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()

        key = read_key()
        if key in ("o", "O", "y", "Y") and self.engine.redact_secret(item):
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
            lines.append(self.build_bottom_bar(width, t("continue_hint")))
            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()
            while read_key() not in ("ENTER", "ESC", "SPACE"):
                pass

    # --- DIALOGUE DE FILTRAGE ---
    def run_filter_dialog(self):
        tools = sorted({f.tool for f in self.findings})
        width = self.get_width()
        height = self.get_height()

        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{C.MAGENTA}{C.BOLD}{t('filter_title')}{C.RESET}", width))
        lines.append("")

        for i, tool_name in enumerate(tools, 1):
            act = f"{C.GREEN}{t('filter_active_tag')}{C.RESET}" if self.active_filter_tool == tool_name else ""
            lines.append(f"    [{i}] {tool_name} {act}")

        lines.append("")
        lines.append(f"    {t('filter_reset')}")
        lines.append(f"    {t('filter_back')}")

        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, t("filter_bottom")))

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

        tag = local_time().strftime("%Y%m%d_%H%M%S")
        md_dest = self.engine.home / f"audit_secrets_ia_{tag}.md"
        json_dest = self.engine.home / f"audit_secrets_ia_{tag}.json"

        lines = []
        lines.append(self.build_top_bar(width))
        lines.append("")
        lines.append(self.center_line(f"{C.BLUE}{C.BOLD}{t('export_title')}{C.RESET}", width))
        lines.append("")
        lines.append(f"    {t('export_md', name=C.CYAN + md_dest.name + C.RESET)}")
        lines.append(f"    {t('export_json', name=C.CYAN + json_dest.name + C.RESET)}")
        lines.append(f"    {t('export_cancel')}")

        while len(lines) < height - 1:
            lines.append("")
        lines = lines[:height - 1]
        lines.append(self.build_bottom_bar(width, t("export_bottom")))

        sys.stdout.write("\033[H" + "\n".join(lines))
        sys.stdout.flush()

        key = read_key()
        if key in ("1", "2"):
            # Animation du spinner d'exportation
            for f in SPINNER_FRAMES[:5]:
                anim_lines = []
                anim_lines.append(self.build_top_bar(width))
                anim_lines.append("")
                anim_lines.append(self.center_line(f"{C.CYAN}{C.BOLD}{f} {t('export_progress')}{C.RESET}", width))
                while len(anim_lines) < height - 1:
                    anim_lines.append("")
                anim_lines = anim_lines[:height - 1]
                anim_lines.append(self.build_bottom_bar(width, t("export_writing")))
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
            lines.append(self.center_line(f"{C.GREEN}{C.BOLD}{t('export_done')}{C.RESET}", width))
            lines.append(self.center_line(f"{C.WHITE}{t('export_file', path=C.CYAN + str(target) + C.RESET)}", width))
            lines.append(self.center_line(f"{C.YELLOW}{t('export_total', count=len(items))}{C.RESET}", width))
            while len(lines) < height - 1:
                lines.append("")
            lines = lines[:height - 1]
            lines.append(self.build_bottom_bar(width, t("export_return")))
            sys.stdout.write("\033[H" + "\n".join(lines))
            sys.stdout.flush()
            while read_key() not in ("ENTER", "SPACE", "ESC"):
                pass

    def export_markdown(self, path: Path, items: list[Finding]):
        is_fr = (get_lang() == "fr")
        user_name = os.getenv("USER") or os.getenv("USERNAME") or "user"
        with open(path, "w", encoding="utf-8") as f:
            if is_fr:
                f.write("# Rapport d'Audit de Sécurité — Transcriptions d'IA\n\n")
                f.write(f"- **Généré le** : {local_time().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"- **Utilisateur** : `{user_name}`\n")
                f.write(f"- **Total secrets identifiés** : {len(items)}\n\n")
                f.write("## Synthèse par Niveau de Sévérité\n\n")
                f.write(f"- **Critique** : {sum(1 for x in items if x.severity in ('CRITIQUE', 'CRITICAL'))}\n")
                f.write(f"- **Élevé** : {sum(1 for x in items if x.severity in ('ÉLEVÉ', 'HIGH'))}\n")
                f.write(f"- **Moyen** : {sum(1 for x in items if x.severity in ('MOYEN', 'MEDIUM'))}\n\n")
                f.write("## Détail des Secrets Détectés\n\n")
                f.write("| # | Sévérité | Catégorie | Outil IA | Projet d'Origine | Valeur (Masquée) | Fichier |\n")
                f.write("|---|---|---|---|---|---|---|\n")
                f.writelines(f"| {idx} | {item.display_severity()} | {item.display_category()} | {item.tool} | {item.project} | `{item.secret_masked}` | `{Path(item.file_path).name}:{item.line_no}` |\n" for idx, item in enumerate(items, 1))
            else:
                f.write("# Security Audit Report — AI Assistant Histories\n\n")
                f.write(f"- **Generated on** : {local_time().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"- **User** : `{user_name}`\n")
                f.write(f"- **Total exposed secrets** : {len(items)}\n\n")
                f.write("## Summary by Severity Level\n\n")
                f.write(f"- **Critical** : {sum(1 for x in items if x.severity in ('CRITIQUE', 'CRITICAL'))}\n")
                f.write(f"- **High** : {sum(1 for x in items if x.severity in ('ÉLEVÉ', 'HIGH'))}\n")
                f.write(f"- **Medium** : {sum(1 for x in items if x.severity in ('MOYEN', 'MEDIUM'))}\n\n")
                f.write("## Detected Secrets Breakdown\n\n")
                f.write("| # | Severity | Category | AI Tool | Origin Project | Value (Masked) | File |\n")
                f.write("|---|---|---|---|---|---|---|\n")
                f.writelines(f"| {idx} | {item.display_severity()} | {item.display_category()} | {item.tool} | {item.project} | `{item.secret_masked}` | `{Path(item.file_path).name}:{item.line_no}` |\n" for idx, item in enumerate(items, 1))

    def export_json(self, path: Path, items: list[Finding]):
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
            lines.append(self.build_bottom_bar(width, t("scan_return_hint")))
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
                lines.append(self.build_bottom_bar(width, t("scan_return_hint")))
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
                    date_str = local_time(stat.st_mtime).strftime("%d/%m/%Y %H:%M:%S")
                except OSError:
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
                if self.confirm_action(t("bak_confirm_one", name=target_bak.stem)):
                    if self.engine.restore_backup(target_bak):
                        self.show_flash_message(t("bak_restored_one", name=target_bak.stem), C.GREEN)
                    else:
                        self.show_flash_message(t("bak_restore_failed"), C.RED)
            elif key in ("a", "A"):
                if self.confirm_action(t("bak_confirm_all", count=len(backups))):
                    cnt = self.engine.restore_all_backups()
                    self.show_flash_message(t("bak_restored_all", count=cnt), C.GREEN)
            elif key in ("p", "P"):
                if self.confirm_action(t("bak_confirm_purge", count=len(backups))):
                    cnt = self.engine.clean_backups()
                    self.show_flash_message(t("bak_purged", count=cnt), C.GREEN)
            elif key in ("q", "Q", "ESC"):
                break

    # --- SURVEILLANCE EN TEMPS RÉEL (WATCHDOG DÉDIÉ) ---
    @staticmethod
    def _list_watched_files(targets: list[Path]) -> list[Path]:
        files = []
        for target in targets:
            if target.is_file():
                files.append(target)
            elif target.is_dir():
                for root, _, names in os.walk(target):
                    for name in names:
                        if not name.endswith((".bak", ".backup")):
                            files.append(Path(root) / name)
        return files

    def run_watchdog_screen(self):
        targets = self.engine.get_target_directories()
        known_mtimes: dict[str, float] = {}

        # Scan initial des mtimes des fichiers surveillés
        for fp in self._list_watched_files(targets):
            try:
                known_mtimes[str(fp)] = fp.stat().st_mtime
            except OSError:
                pass

        # Un secret n'est signalé qu'une fois : les sessions IA sont réécrites en continu,
        # et chaque modification rescanne le fichier entier.
        alerted = {(f.category, f.secret_raw, f.file_path) for f in self.findings}

        events_log: list[str] = [
            f"{C.GRAY}[{local_time().strftime('%H:%M:%S')}] {t('watchdog_started', files=len(known_mtimes))}{C.RESET}"
        ]
        alerts_count = 0
        scans_count = 0
        pulse = False

        # Hors terminal (service, redirection), pas de lecture clavier : arrêt par signal.
        interactive = sys.stdin.isatty()
        if interactive and not IS_WINDOWS:
            fd = sys.stdin.fileno()
            old_term = termios.tcgetattr(fd)
            # cbreak et non raw : raw coupe OPOST, et chaque "\n" affiché décalerait l'écran en escalier.
            tty.setcbreak(fd)

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
                if not interactive:
                    time.sleep(1.0)
                elif IS_WINDOWS:
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
                now_ts = local_time().strftime("%H:%M:%S")
                for cp in self._list_watched_files(targets):
                    sp = str(cp)
                    try:
                        mtime = cp.stat().st_mtime
                    except OSError:
                        continue

                    # Nouveau fichier ou modification détectée
                    if sp not in known_mtimes or mtime > known_mtimes[sp]:
                        is_new = (sp not in known_mtimes)
                        known_mtimes[sp] = mtime
                        scans_count += 1

                        file_findings = self.engine.scan_single_file(cp)
                        new_findings = []
                        for f in file_findings:
                            key = (f.category, f.secret_raw, f.file_path)
                            if key not in alerted:
                                alerted.add(key)
                                new_findings.append(f)
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
                        elif not file_findings:
                            action_name = t("watchdog_act_creation") if is_new else t("watchdog_act_modification")
                            events_log.append(f"{C.GRAY}[{now_ts}] {t('watchdog_clean_log', act=action_name, file=cp.name)}{C.RESET}")

                if len(events_log) > 50:
                    events_log = events_log[-50:]

        finally:
            if interactive and not IS_WINDOWS:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_term)


# --- MISE À JOUR (npm) ---
NPM_PACKAGE = "ai-secret-scout"


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", text.split("-")[0])[:3])


def run_update() -> int:
    """Seul accès réseau de l'outil, et uniquement sur demande : c'est npm qui interroge le registre."""
    npm = os.getenv("AISCOUT_NPM") or shutil.which("npm")
    if not npm or not os.path.isfile(npm):
        print(f"{C.RED}{t('update_no_npm')}{C.RESET}", file=sys.stderr)
        return 1

    def npm_out(*args: str) -> str:
        proc = subprocess.run([npm, *args], capture_output=True, text=True, timeout=60, check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            raise RuntimeError(detail[-1] if detail else f"code {proc.returncode}")
        return proc.stdout.strip()

    print(f"{C.GRAY}{t('update_checking')}{C.RESET}")
    try:
        latest = npm_out("view", NPM_PACKAGE, "version")
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"{C.RED}{t('update_check_failed', error=exc)}{C.RESET}", file=sys.stderr)
        return 1

    if parse_version(latest) <= parse_version(VERSION):
        print(f"{C.GREEN}{t('update_uptodate', version=VERSION)}{C.RESET}")
        return 0

    print(f"{C.YELLOW}{C.BOLD}{t('update_available', current=VERSION, latest=latest)}{C.RESET}")
    install_cmd = ["npm", "install", "-g", f"{NPM_PACKAGE}@latest"]
    script = Path(__file__).resolve()

    if "_npx" in script.parts:
        print(t("update_npx", cmd=f"npx {NPM_PACKAGE}@latest"))
        return 0
    try:
        global_pkg = (Path(npm_out("root", "-g")) / NPM_PACKAGE).resolve()
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        global_pkg = None
    if global_pkg is None or global_pkg not in script.parents:
        # Clone, dépendance locale ou installation par un autre gestionnaire : on n'écrase rien.
        print(t("update_manual", cmd=" ".join(install_cmd)))
        return 0

    print(f"{C.GRAY}{t('update_running', cmd=' '.join(install_cmd))}{C.RESET}")
    code = subprocess.run([npm, *install_cmd[1:]], check=False).returncode
    if code != 0:
        print(f"{C.RED}{t('update_failed', code=code)}{C.RESET}", file=sys.stderr)
        return code
    print(f"{C.GREEN}{C.BOLD}{t('update_done', latest=latest)}{C.RESET}")
    return 0


# --- POINT D'ENTRÉE ---
def main():
    # Détection précoce du paramètre --lang / -l pour adapter le message d'aide argparse
    for idx, a in enumerate(sys.argv[:-1]):
        if a in ("--lang", "-l"):
            set_lang(sys.argv[idx + 1])
            break

    parser = argparse.ArgumentParser(
        prog="aiscout",
        description=t("cli_desc"),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", nargs="?", choices=["update"], help=t("cli_help_update"))
    parser.add_argument("--version", "-V", action="version", version=f"aiscout {VERSION}", help=t("cli_help_version"))
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

    if args.command == "update":
        sys.exit(run_update())

    user_home = Path(args.home_dir) if args.home_dir else None
    engine = ScoutEngine(user_home=user_home)

    if args.list_rules:
        print(f"\n{C.CYAN}{C.BOLD}◈  AI SECRET SCOUT — {t('cli_rules_title')} ({len(engine.patterns)})  ◈{C.RESET}\n")
        print(f" {'#':<3} │ {t('col_severity'):<10} │ {t('cli_rule_name'):<35} │ {t('cli_rule_desc'):<45}")
        print("─" * 98)
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
        with contextlib.suppress(OSError):
            sys.stderr.close()
        sys.exit(0)
