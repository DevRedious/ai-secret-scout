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

  <h2>AI Secret Scout (<code>aiscout</code>) — v2.4.5</h2>

  <p align="center">
    <!-- Ligne 1 : badges techno & plateforme -->
    <a href="https://github.com/DevRedious/ai-secret-scout/actions/workflows/ci.yml"><img src="https://github.com/DevRedious/ai-secret-scout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://www.npmjs.com/package/ai-secret-scout"><img src="https://img.shields.io/npm/v/ai-secret-scout?logo=npm&amp;color=CB3837" alt="npm version"></a>
    <a href="https://www.npmjs.com/package/ai-secret-scout"><img src="https://img.shields.io/npm/dm/ai-secret-scout?logo=npm&amp;color=CB3837" alt="npm downloads"></a>
    <a href="https://socket.dev/npm/package/ai-secret-scout"><img src="https://badge.socket.dev/npm/package/ai-secret-scout" alt="Socket Badge"></a>
    <a href="./LICENSE"><img src="https://img.shields.io/npm/l/ai-secret-scout?color=blue" alt="License MIT"></a>
  </p>

  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&amp;logoColor=white" alt="Python 3.10+">
    <img src="https://img.shields.io/badge/Interface-TUI%20Plein%20%C3%89cran-06B6D4?logo=gnometerminal&amp;logoColor=white" alt="TUI Plein Écran">
    <img src="https://img.shields.io/badge/D%C3%A9pendances-Zero%20External-22c55e?logo=python&amp;logoColor=white" alt="Zéro Dépendance">
    <img src="https://img.shields.io/badge/Watchdog-Temps%20R%C3%A9el%20%26%20Desktop%20Alerts-F59E0B?logo=airplayaudio&amp;logoColor=white" alt="Watchdog Temps Réel">
    <img src="https://img.shields.io/badge/Safe%20Restore-Gestionnaire%20Backups-7C3AED?logo=securityscorecard&amp;logoColor=white" alt="Safe Restore">
    <img src="https://img.shields.io/badge/Plateforme-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20WSL-0078D6?logo=windows&amp;logoColor=white" alt="Linux | Windows | macOS | WSL">
  </p>

  <p align="center">
    <!-- Ligne 2 : thématique & écosystèmes IA audités -->
    <img src="https://img.shields.io/badge/Claude%20Code-Audit%C3%A9-D97706?logo=anthropic&amp;logoColor=white" alt="Claude Code">
    <img src="https://img.shields.io/badge/Antigravity-Audit%C3%A9-4285F4?logo=google&amp;logoColor=white" alt="Antigravity">
    <img src="https://img.shields.io/badge/OpenAI%20Codex-Audit%C3%A9-10A37F?logo=openai&amp;logoColor=white" alt="Codex">
    <img src="https://img.shields.io/badge/GitHub%20Copilot-Audit%C3%A9-000000?logo=githubcopilot&amp;logoColor=white" alt="GitHub Copilot">
    <img src="https://img.shields.io/badge/Cursor%20%26%20Aider-Audit%C3%A9-8B5CF6" alt="Cursor &amp; Aider">
  </p>

  <p align="center">
    <i>Audit, surveillance temps réel (Watchdog), alertes bureau, détection heuristique et caviardage sécurisé de fuites de secrets dans les historiques d'IA.</i>
  </p>

  <p align="center">
    <b><a href="./README.md">🇬🇧 English documentation</a></b> | <b>🇫🇷 Documentation en français</b>
  </p>
</div>

---

## 📑 Sommaire
1. [Pourquoi ce projet ?](#-pourquoi-ce-projet-)
2. [Nouveautés majeures de la v2.4.0](#-nouveautés-majeures-de-la-v240)
3. [Lancement rapide](#-lancement-rapide)
4. [Interface TUI & Navigation](#-interface-tui--navigation)
5. [Surveillance Temps Réel (Watchdog) & Notifications Bureau](#-surveillance-temps-réel-watchdog--notifications-bureau)
6. [Gestionnaire de Sauvegardes & Restauration (`Safe Restore`)](#-gestionnaire-de-sauvegardes--restauration-safe-restore)
7. [Écosystèmes d'IA Audités](#-écosystèmes-dia-audités)
8. [Moteur de Détection & Signatures (18 intégrées + Custom)](#-moteur-de-détection--signatures-18-intégrées--custom)
9. [Fichier de Règles Personnalisées (`rules.json`)](#-fichier-de-règles-personnalisées-rulesjson)
10. [Algorithmes Anti-Faux-Positifs](#-algorithmes-anti-faux-positifs)
11. [Assainissement & Caviardage Sécurisé (`Safe Redact`)](#-assainissement--caviardage-sécurisé-safe-redact)
12. [Raccourcis Clavier & Contrôles](#-raccourcis-clavier--contrôles)
13. [Mode Scripting / CLI & Automatisation](#-mode-scripting--cli--automatisation)
14. [Architecture Technique](#-architecture-technique)

---

## 🔍 Pourquoi ce projet ?

Lors de l'utilisation d'assistants de codage autonomes (**Claude Code**, **Google Antigravity / Gemini CLI**, **OpenAI Codex**, **GitHub Copilot CLI**, **Cursor**), les modèles enregistrent des transcriptions complètes de chaque échange dans votre espace personnel (`~/.claude`, `~/.gemini`, `%APPDATA%\Cursor`, etc.).

### Le problème
1. **Fuites passives de secrets** : Lorsqu'un agent exécute une commande terminal (ex. `infisical secrets`, `ssh`, `curl`, ou un script `.env`), la sortie brute de la commande est enregistrée en clair dans les logs locaux.
2. **Fuites actives dans les prompts** : Lorsqu'un utilisateur colle une clé d'API, un token GitHub ou un mot de passe directement dans la boîte de dialogue, cette valeur est conservée indéfiniment sur le disque.
3. **Absence de protection native** : Même si certains assistants avertissent l'utilisateur de la fuite, ils ne suppriment **jamais** la valeur enregistrée sur le disque.
4. **Persistance invisible** : Les secrets restent vulnérables aux malwares locaux, aux sauvegardes cloud accidentelles ou aux partages de dépôts.

**AI Secret Scout (`aiscout`)** comble cette faille critique : il surveille et audite l'ensemble des historiques d'IA sur votre machine, attribue chaque secret à son **projet d'origine**, identifie son **contexte d'usage**, et permet de le **caviarder chirurgicalement** avec sauvegarde de secours et restauration instantanée.

---

## 🌟 Nouveautés majeures de la v2.4.0

* **🪟 Support natif complet de Windows 10/11 & Cross-Platform unifié** :
  * Fonctionne nativement dans **PowerShell**, **Windows Terminal** et **CMD** sans dépendre de WSL.
  * Gestion non bloquante du clavier sous Windows via `msvcrt` et activation automatique du mode VT100/ANSI.
  * Notifications toast discrètes en arrière-plan sous Windows via PowerShell (`System.Windows.Forms.NotifyIcon`).
  * Détection automatique des chemins d'IA sous Windows (`%APPDATA%\Cursor`, `%APPDATA%\Claude`, `%LOCALAPPDATA%`, etc.).
  * Détecteur d'environnement Node.js/Python avec commandes d'installation adaptées (`winget install Python.Python.3.12` sur Windows, gestionnaires de paquets sur Linux/macOS).

* **🌐 Basculement de langue bilingue instantané (`[L]` FR ⇄ EN)** :
  * Appuyez simplement sur `[L]` depuis le menu principal pour basculer instantanément l'ensemble de l'interface, des explications, des rapports et des fiches d'audit entre **Français** et **Anglais**.
  * Détection automatique de la locale système au démarrage (`LANG`, `LC_ALL`, `locale.getdefaultlocale()`).

* **📡 Surveillance continue en temps réel (Mode Watchdog)** :
  * Détecte instantanément l'écriture ou la modification d'un fichier de session IA sans solliciter le CPU.
  * Envoi immédiat d'une **notification de bureau native** (`notify-send` sous Linux KDE Plasma Wayland / GNOME, et toasts PowerShell sous Windows).
  * Voyant de pulsation visuelle en direct `🟢 [VEILLE ACTIVE]` et journal des événements défilant en temps réel.
  * Accessible via le menu TUI `[8]` ou en ligne de commande directe : `aiscout --watch`.

* **↩️ Gestionnaire de sauvegardes & Restauration (`Safe Restore`)** :
  * Tableau TUI interactif dédié à la gestion des sauvegardes (`.bak`) créées lors des opérations de caviardage.
  * Restauration unitaire chirurgicale (`[R]`), restauration complète de tous les originaux (`[A]`), ou purge définitive (`[P]`).
  * Commandes CLI dédiées : `aiscout --restore` et `aiscout --clean-backups`.

* **🔍 Recherche interactive (`/`) & Tri dynamique (`S`/`D`/`O`) dans le tableau TUI** :
  * Touche `/` : Champ de recherche textuel instantané (filtre en direct par catégorie, outil, projet, chemin ou valeur).
  * Touches de tri dynamique :
    * `S` : Tri par sévérité décroissante (`🔴 CRITIQUE` > `🟡 ÉLEVÉ` > `🔵 MOYEN`).
    * `D` : Tri par date / fraîcheur de session (les plus récents en premier).
    * `O` : Tri alphabétique par outil d'IA.
  * Réinitialisation rapide via `Backspace` ou `Échap`.

* **⚙️ Moteur de règles personnalisées & 4 nouvelles signatures** :
  * Chargement automatique de règles définies par l'utilisateur dans `~/.config/aiscout/rules.json` (ou `%APPDATA%\aiscout\rules.json` sous Windows).
  * 4 nouvelles signatures intégrées majeures :
    * **GitLab Personal Access Token** (`glpat-[0-9a-zA-Z_\-]{20,}`)
    * **HuggingFace Access Token** (`hf_[a-zA-Z0-9]{34,}`)
    * **Resend API Key** (`re_[a-zA-Z0-9_\-]{24,}`)
    * **Supabase / JWT Secret** (`eyJ...`)
  * Commande d'inspection CLI : `aiscout --list-rules` listant les 18 règles intégrées et les règles custom.

---

## 🚀 Lancement rapide

### Sur Linux, macOS & WSL

```bash
# ⚡ Exécution instantanée sans installation préalable
npx ai-secret-scout
# ou avec bun
bunx ai-secret-scout

# 📦 Installation globale permanente (recommandée)
npm install -g ai-secret-scout
# ou avec bun
bun add -g ai-secret-scout

# Une fois installé, les commandes aiscout et ai-secret-scout sont disponibles partout :
aiscout
```

### Sur Windows (PowerShell / Windows Terminal / CMD)

```powershell
# ⚡ Exécution directe
npx ai-secret-scout

# 📦 Installation globale
npm install -g ai-secret-scout

# Si Python n'est pas encore installé sur votre machine Windows :
winget install Python.Python.3.12

# Lancement immédiat
aiscout
```

### Options en ligne de commande usuelles

```bash
# Surveillance temps réel (Watchdog) avec alertes bureau
aiscout --watch

# Restauration instantanée de tous les fichiers originaux depuis leurs sauvegardes .bak
aiscout --restore

# Nettoyage définitif de tous les fichiers .bak
aiscout --clean-backups

# Liste exhaustive de toutes les règles actives (intégrées + personnalisées)
aiscout --list-rules
```

L'application bascule automatiquement votre terminal dans un écran alternatif (`\033[?1049h`). À la fermeture (`Q`), votre terminal d'origine est intégralement restauré sans résidu d'affichage.

---

## 🎨 Interface TUI & Navigation

Le moteur TUI autonome d'`aiscout` (pure bibliothèque standard Python) s'adapte dynamiquement aux dimensions de votre terminal sans jamais tronquer le menu ni provoquer de défilement parasite.

### 1. Tableau de bord & Menu d'accueil interactif (Hub central)

```text
 ◈ AISCOUT v2.4.5 │ Utilisateur : dev_redious │ Machine : poste-travail       12/09/2026 22:30

                 █████╗ ██╗   ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
                ██╔══██╗██║   ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
                ███████║██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
                ██╔══██║██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
                ██║  ██║██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
                ╚═╝  ╚═╝╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   

               ◈  A U D I T   D E S   S E C R E T S   E N   C L A I R   D A N S   L E S   I A  ◈
                Claude Code • Antigravity / Gemini • Codex • GitHub Copilot • Cursor

           [ 🔴 19 CRITIQUES │ 🟡 1 ÉLEVÉ │ 🔵 1 MOYEN ]  ◈  TOTAL : 21 SECRETS EXPOSÉS 

        ║  ▶  [1]  🔍   AUDIT COMPLET DES SESSIONS IA                                 ║
        │     [2]  📋   EXPLORATEUR DE SECRETS (TABLEAU TUI)                          │
        │     [3]  👁️    MODE RÉVÉLATION (VALEURS EN CLAIR)                           │
        │     [4]  🏷️    FILTRER PAR OUTIL IA OU PROJET                                │
        │     [5]  💾   EXPORTER LE DOSSIER D'AUDIT                                   │
        │     [6]  🛡️    ASSAINISSEMENT & CAVIARDAGE SÉCURISÉ                         │
        │     [7]  ↩️    GESTIONNAIRE DES BACKUPS (.BAK)                              │
        │     [8]  📡   SURVEILLANCE TEMPS RÉEL (WATCHDOG)                            │
        │     [9]  🚪   QUITTER L'APPLICATION                                         │

        ╭─ ACTION SÉLECTIONNÉE ───────────────────────────────────────────────────────╮
        │  💡  Naviguer au clavier dans la liste des secrets détectés et inspecter    │
        ╰─────────────────────────────────────────────────────────────────────────────╯

  [↑/↓] Naviguer │ [Entrée] Valider │ [1-9] Accès direct │ [L] Langue (FR/EN) │ [Q] Quitter
```

### 2. Explorateur de secrets (Tableau interactif, Tri dynamique & Recherche)

La vue tableau permet de parcourir l'intégralité des fuites identifiées avec pagination fluide, tri multi-critères et recherche plein texte instantanée :

```text
 ◈ AISCOUT v2.4.5 │ Utilisateur : dev_redious │ Machine : poste-travail       12/09/2026 22:30

   📋 EXPLORATEUR DE SECRETS (1/21) — Mode : MASQUÉ 🛡️ │ Tri : Sévérité (🔴 > 🟡 > 🔵)

 #   │ SÉVÉRITÉ   │ CATÉGORIE                    │ OUTIL IA           │ PROJET                 │ VALEUR DU SECRET       
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 1   │ 🔴 CRITIQUE │ Clé Privée (SSH / RSA / ECC) │ Claude Code        │ ~                      │ ----****************...
 2   │ 🔴 CRITIQUE │ Clé Privée (SSH / RSA / ECC) │ Claude Code        │ ~                      │ ----****************...
 3   │ 🔴 CRITIQUE │ GitHub Token (PAT / Fine-Gr) │ Claude Code        │ ~/Documents/Dev/RIL... │ ghp_****************...
 4   │ 🔴 CRITIQUE │ Infisical / Coolify Token    │ Claude Code        │ ~/Documents/Dev/RIL... │ st.4****************...
 5   │ 🟡 ÉLEVÉ    │ Discord Bot Token            │ Claude Code        │ ~/Documents/Dev/RIL... │ MTE2****************...
 6   │ 🔵 MOYEN    │ Mot de passe passé en comman │ Claude Code        │ ~/Documents/Dev/RIL... │ pass****************...
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  [↑/↓] Naviguer │ [Entrée] Fiche │ [/] Chercher │ [S/D/O] Trier │ [R] Mode │ [C] Caviarder │ [Q] Retour
```

#### Recherche interactive plein texte (`/`)
En appuyant sur `/`, une boîte de saisie inline s'ouvre sur la barre inférieure. Le tableau se met à jour en temps réel (filtre instantané sur la catégorie, l'outil, le projet, le fichier ou la valeur du secret) :

```text
 ◈ AISCOUT v2.4.5 │ Utilisateur : dev_redious │ Machine : poste-travail       12/09/2026 22:30

   📋 EXPLORATEUR DE SECRETS (1/3) — Mode : MASQUÉ 🛡️ │ Tri : Sévérité (🔴 > 🟡 > 🔵)
         🔍 Recherche active : "github" (3 secrets trouvés) │ [Backspace/Esc] Effacer 

 #   │ SÉVÉRITÉ   │ CATÉGORIE                    │ OUTIL IA           │ PROJET                 │ VALEUR DU SECRET       
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 1   │ 🔴 CRITIQUE │ GitHub Token (PAT / Fine-Gr) │ Claude Code        │ ~/Documents/Dev/RIL... │ ghp_****************...
 2   │ 🔴 CRITIQUE │ GitHub Token (PAT / Fine-Gr) │ Claude Code        │ ~/Documents/Dev/RIL... │ ghp_****************...
 3   │ 🔴 CRITIQUE │ GitHub Token (PAT / Fine-Gr) │ Antigravity (Gemi) │ Session Antigravity    │ ghp_****************...
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  [↑/↓] Naviguer │ [Entrée] Fiche │ [/] Chercher │ [S/D/O] Trier │ [R] Mode │ [C] Caviarder │ [Q] Retour
```

### 3. Fiche détaillée d'audit (Modal Card)

En pressant `Entrée` sur une ligne du tableau, une fiche d'audit chirurgicale s'affiche avec le contexte exact d'usage et l'extrait de log :

```text
 ◈ AISCOUT v2.4.5 │ Utilisateur : dev_redious │ Machine : poste-travail       12/09/2026 22:30

   ╭──────────────────────────────────────────────────────────────────────────────────╮
   │  FICHE D'AUDIT DU SECRET DÉTECTÉ                                                 │
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  Catégorie      : Clé Privée (SSH / RSA / ECC)                                   │
   │  Sévérité       : CRITIQUE                                                       │
   │  Outil IA       : Claude Code                                                    │
   │  Projet d'origine: ~                                                             │
   │  Date session   : 2026-08-20 14:06                                               │
   │  Emplacement    : 20b45f26-98f1-4273-a834-32243f11d067.jsonl:23                  │
   │  Contexte       : Sortie d'outil exécuté (commande bash, .env ou infisical)      │
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  VALEUR EN CLAIR: -----BEGIN OPENSSH PRIVATE KEY-----                            │
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  Extrait Log    : │ SECRET NAME                        │ SECRET VALUE            │
   ├──────────────────────────────────────────────────────────────────────────────────┤
   │  Action conseillée: 1. Procéder à la rotation de la clé/identifiant.             │
   │                   2. Caviarder ce fichier avec [C] pour effacer la trace.        │
   ╰──────────────────────────────────────────────────────────────────────────────────╯

  [C] Caviarder ce secret  │  [Esc] ou [Q] Retour à la liste
```

### 4. Animation de chargement en temps réel (Spinner & Jauge dynamique)

Lors de l'audit initial, du caviardage ou de l'exportation des dossiers d'audit, une animation à 100ms affiche l'étape en cours et la progression :

```text
 ◈ AISCOUT v2.4.5 │ Utilisateur : dev_redious │ Machine : poste-travail       12/09/2026 22:30

                 █████╗ ██╗   ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
                ██╔══██╗██║   ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
                ███████║██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
                ██╔══██║██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
                ██║  ██║██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
                ╚═╝  ╚═╝╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   

               ⚡ AUDIT DE SÉCURITÉ EN COURS D'EXÉCUTION...

   ╭──────────────────────────────────────────────────────────────────╮
   │   ⠹  [▰▰▰▰▰▰▰▰▰▰▰▰▰▰▰▱▱▱▱▱▱▱▱▱▱▱]   58%                         │
   │   Analyse : Infisical / Coolify Token                            │
   ╰──────────────────────────────────────────────────────────────────╯

  Veuillez patienter pendant l'analyse...
```

### 🌟 Points forts du moteur TUI
* **Gestion des flèches & Entrées multiplateforme** : Décodage non bloquant (`msvcrt` sous Windows, `termios`/`tty`/`select` sous POSIX Linux/macOS) avec lookahead 100ms absorbant toutes les séquences d'échappement ANSI (`\x1b[A`, `\x1b[B`, `\x1bOA`, `\x1bOB`, consoles Linux et modificateurs Shift/Ctrl).
* **Layout auto-adaptatif (zéro coupure)** :
  * Barre supérieure clouée à la **ligne 1**.
  * Barre inférieure clouée à la **dernière ligne du terminal**.
  * Hauteur ≥ 42 : Grandes cartes épaisses avec double bordure (`╔══════╗`).
  * Hauteur 27–41 : Boutons barres compacts en surbrillance avec boîte de description contextuelle.
  * Hauteur < 27 : En-tête ultra-compact assurant que 100% des 9 actions restent immédiatement accessibles.
* **Précision typographique Unicode** : Prise en charge des largeurs de caractères variables (`unicodedata.east_asian_width`) pour garantir l'alignement strict des bordures verticales avec les emojis.

---

## 📡 Surveillance Temps Réel (Watchdog) & Notifications Bureau

Le mode **Watchdog** transforme `aiscout` en un gardien silencieux en arrière-plan :

```text
 ◈ AISCOUT v2.4.5 │ Utilisateur : dev_redious │ Machine : poste-travail       12/09/2026 22:21

             📡 SURVEILLANCE EN TEMPS RÉEL (WATCHDOG)  │  🟢 [VEILLE ACTIVE]
       Détecte les sessions IA en écriture et notifie instantanément sur le bureau (Linux / Windows)

   ╭──────────────────────────────────────────────────────────────────────────────╮
   │ Fichiers écoutés : 5498 │ Scans live : 14 │ Alertes déclenchées : 0          │
   ╰──────────────────────────────────────────────────────────────────────────────╯

   ╭─ 📜 JOURNAL DES ÉVÉNEMENTS RÉCENTS (14 logs) ────────────────────────────────╮
   │  [22:20:10] 🚀 Surveillance démarrée — 5498 fichiers d'historique IA sous éc │
   │  [22:20:45] ℹ️  Modification vérifiée saine : history.jsonl                  │
   │  [22:21:02] ⚠️ ALERTE : GitHub Token (CRITIQUE) dans Claude Code (~/ProjetX) │
   ╰──────────────────────────────────────────────────────────────────────────────╯

  [Q] ou [Esc] Quitter la surveillance et revenir au menu principal
```

### Mécanismes clés
1. **Écoute non-intrusive** : Scrute les horodatages `mtime` des répertoires d'IA sans lire le disque inutilement.
2. **Scan chirurgical** : Dès qu'une modification ou un nouveau fichier est détecté, seul ce fichier est analysé à chaud avec `scan_single_file()`.
3. **Alertes de bureau natives** : Déclenchement via `notify-send` avec niveau d'urgence `critical` sous Linux (KDE Plasma Wayland, GNOME) ou notifications toast discrètes PowerShell sous Windows.
4. **Signal d'alerte sonore** : Bip terminal (`\a`) lors de chaque détection de secret critique.

---

## ↩️ Gestionnaire de Sauvegardes & Restauration (`Safe Restore`)

Le menu `[7]` offre un contrôle absolu sur les fichiers de sauvegarde générés lors des opérations de caviardage :

```text
 ◈ AISCOUT v2.4.5 │ Utilisateur : dev_redious │ Machine : poste-travail       12/09/2026 22:22

             ↩️  GESTIONNAIRE DES SAUVEGARDES & RESTAURATION (.BAK)
          Restaurer les fichiers originaux avant caviardage ou purger les sauvegardes.

 #   │ FICHIER SOURCE                   │ OUTIL IA             │ TAILLE     │ DATE SAUVEGARDE   
──────────────────────────────────────────────────────────────────────────────────────────
 1   │ 20b45f26-98f1-4273-a834...jsonl  │ Claude Code          │ 412.3 Ko   │ 12/09/2026 22:15  
 2   │ history.jsonl                    │ Antigravity (Gemini) │ 84.1 Ko    │ 12/09/2026 21:50  
──────────────────────────────────────────────────────────────────────────────────────────

  [↑/↓] Naviguer │ [R] Restaurer sélection │ [A] Tout restaurer │ [P] Purger (.bak) │ [Esc] Retour
```

* **`[R]` Restaurer le fichier sélectionné** : Remplace le fichier courant par sa version originale et supprime le `.bak`.
* **`[A]` Tout restaurer** : Restaure l'ensemble des sauvegardes en une seule commande après confirmation.
* **`[P]` Purger définitivement** : Supprime tous les `.bak` pour finaliser définitivement l'assainissement et libérer l'espace disque.

---

## 📁 Écosystèmes d'IA Audités

`aiscout` recherche automatiquement les historiques dans toute session utilisateur :

| Assistant IA | Chemins analysés | Types de fichiers |
| :--- | :--- | :--- |
| **Claude Code** | `~/.claude/projects/`, `~/.claude/history.jsonl`, `~/.claude/handoff/` | `JSONL`, `JSON` |
| **Google Antigravity / Gemini CLI** | `~/.gemini/antigravity-cli/brain/`, `~/.gemini/antigravity-cli/history.jsonl`, `conversations/` | `JSONL`, `JSON` |
| **OpenAI Codex CLI** | `~/.codex/sessions/`, `~/.codex/history.jsonl` | `JSONL`, `JSON` |
| **GitHub Copilot CLI** | `~/.copilot/session-state/` | `JSON`, `LOG` |
| **Cursor & Aider** | `~/.cursor/projects/`, `~/.cursor/plans/`, `.aider.chat.history.md` | `JSON`, `MD` |

---

## 🛡️ Moteur de Détection & Signatures (18 intégrées + Custom)

| Catégorie | Sévérité | Exemple de pattern détecté |
| :--- | :---: | :--- |
| **GitHub Token (PAT / Fine-Grained)** | 🔴 **CRITIQUE** | `ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}` |
| **GitLab Personal Access Token** *(Nouveau)* | 🔴 **CRITIQUE** | `glpat-[0-9a-zA-Z_\-]{20,}` |
| **HuggingFace Token** *(Nouveau)* | 🔴 **CRITIQUE** | `hf_[a-zA-Z0-9]{34,}` |
| **Clé Privée (SSH / RSA / ECC / PEM)** | 🔴 **CRITIQUE** | `-----BEGIN (?:OPENSSH\|RSA\|DSA\|EC\|ENCRYPTED\|PGP)? PRIVATE KEY-----` |
| **Stripe Secret Key** | 🔴 **CRITIQUE** | `sk_live_[0-9a-zA-Z]{24,}`, `rk_live_[0-9a-zA-Z]{24,}` |
| **Base de données (URI avec MDP)** | 🔴 **CRITIQUE** | `postgres://user:password@host`, `mysql://...`, `mongodb://...` |
| **Infisical / Coolify Token** | 🔴 **CRITIQUE** | `st.[a-f0-9]{24}.[a-f0-9]{64}`, `inf_sec_...`, `inf_tok_...` |
| **Resend API Key** *(Nouveau)* | 🟡 **ÉLEVÉ** | `re_[a-zA-Z0-9_\-]{24,}` |
| **Supabase / JWT Secret** *(Nouveau)* | 🟡 **ÉLEVÉ** | `eyJ[a-zA-Z0-9_-]{10,}\.eyJ...` |
| **Anthropic API Key** | 🟡 **ÉLEVÉ** | `sk-ant-api03-[A-Za-z0-9_-]{30,}` |
| **OpenAI API Key** | 🟡 **ÉLEVÉ** | `sk-proj-[A-Za-z0-9_-]{32,}` |
| **AWS Access Key** | 🟡 **ÉLEVÉ** | `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}` |
| **Discord Bot Token** | 🟡 **ÉLEVÉ** | `[MN][A-Za-z\d]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,39}` |
| **Slack Token** | 🟡 **ÉLEVÉ** | `xox[baprs]-[0-9a-zA-Z]{10,48}` |
| **Tailscale Auth Key** | 🟡 **ÉLEVÉ** | `tskey-auth-[a-zA-Z0-9_-]{20,}` |
| **Variable d'environnement sensible** | 🟡 **ÉLEVÉ** | `PGPASSWORD=...`, `MYSQL_PWD=...`, `API_KEY=...` |
| **Mot de passe dans le Prompt** | 🟡 **ÉLEVÉ** | `"mon mot de passe est ..."`, `"mdp: ..."` |
| **Mot de passe passé en commande CLI**| 🔵 **MOYEN** | `sshpass -p ...`, `mysql -p...`, `--password ...` |

---

## ⚙️ Fichier de Règles Personnalisées (`rules.json`)

`aiscout` permet d'ajouter vos propres signatures propres à votre entreprise ou projets dans :
`~/.config/aiscout/rules.json`

```json
{
  "_comment": "Ajoutez vos règles personnalisées ici. Format: Nom: {regex, severity, description}",
  "Jeton Interne Entreprise": {
    "regex": "\\bcorp_sec_[a-zA-Z0-9]{24,}\\b",
    "severity": "CRITIQUE",
    "description": "Jeton secret d'accès à l'API interne d'entreprise."
  },
  "Clé API Partenaire": {
    "regex": "\\bpartner_live_[a-z0-9]{32}\\b",
    "severity": "ÉLEVÉ",
    "description": "Clé d'authentification API partenaire B2B."
  }
}
```

Toutes les règles définies dans ce fichier sont automatiquement identifiées avec le suffixe `[CUSTOM]` et intégrées à l'audit complet, au watchdog et au tableau TUI.

---

## 🧠 Algorithmes Anti-Faux-Positifs

Pour éliminer le bruit et les faux positifs fréquents, `aiscout` applique 5 filtres rigoureux :

1. **Calcul d'entropie de Shannon ($H$)** :
   $$H(X) = -\sum_{i=1}^n P(x_i) \log_2 P(x_i)$$
   Les chaînes avec une entropie insuffisante (< 3.2 bits/symbole) sont éliminées.
2. **Diversité des classes de caractères** :
   Les secrets doivent réunir au moins 3 types distincts (minuscules, majuscules, chiffres, symboles).
3. **Liste noire contextuelle de Placeholders** :
   Exclusion stricte des exemples de documentation : `your_token`, `dummy`, `example`, `change_me`, `sk-ant-xxx`, etc.
4. **Validation de bloc pour clés privées** :
   Les mentions textuelles isolées sont ignorées ; seules les clés comportant un en-tête, un corps cryptographique et un pied (`-----END ...`) sont retenues.
5. **Bouclier miroir anti-auto-détection** :
   L'outil ignore ses propres expressions régulières, ses scripts et les mentions `[REDACTED_BY_AISCOUT]`.

---

## 🛡️ Assainissement & Caviardage Sécurisé (`Safe Redact`)

* **Caviardage ciblé (`[C]`)** : Remplacement unitaire du secret par `[REDACTED_BY_AISCOUT]`.
* **Caviardage global (`[6]`)** : Assainissement en un clic de l'ensemble des sessions compromises.
* **Garantie `.bak`** : Création automatique d'une copie conforme avant modification du fichier original.
* **Intégration Safe Restore** : Toute modification peut être annulée instantanément depuis le menu `[7]`.

---

## 🕹️ Raccourcis Clavier & Contrôles

### Menu Principal
| Touche | Action |
| :--- | :--- |
| `↑` / `↓` ou `k` / `j` ou `z` / `s` | Déplacer le curseur de sélection |
| `Entrée` / `Espace` / `→` | Valider et exécuter l'action sélectionnée |
| `1` à `9` | Accès direct au menu par son numéro |
| `L` | Basculer la langue à la volée (`FR` / `EN`) |
| `Q` ou `Ctrl+C` | Quitter proprement l'application |

### Explorateur de Secrets (Tableau TUI)
| Touche | Action |
| :--- | :--- |
| `↑` / `↓` ou `k` / `j` | Naviguer ligne par ligne |
| `PageUp` / `PageDown` | Faire défiler par page entière |
| `Entrée` | Ouvrir la **fiche détaillée** du secret survolé |
| `/` | **Recherche interactive** par mot-clé (catégorie, outil, projet, valeur) |
| `S` | **Trier par sévérité** (`🔴 CRITIQUE` > `🟡 ÉLEVÉ` > `🔵 MOYEN`) |
| `D` | **Trier par date** de session (plus récents en premier) |
| `O` | **Trier par outil IA** (ordre alphabétique) |
| `Backspace` / `Échap` | Réinitialiser la recherche active |
| `R` | Basculer entre le mode **Masqué** (`ghp_****...`) et **En Clair** |
| `C` | Caviarder chirurgicalement le secret sélectionné |
| `Q` ou `Échap` | Retourner au menu principal |

### Surveillance Temps Réel (Watchdog) & Backups
| Touche | Action |
| :--- | :--- |
| `R` *(Backups)* | Restaurer la sauvegarde `.bak` sélectionnée |
| `A` *(Backups)* | Restaurer l'intégralité des sauvegardes |
| `P` *(Backups)* | Purger définitivement tous les fichiers `.bak` |
| `Q` ou `Échap` | Quitter l'écran et revenir au menu principal |

---

## ⚙️ Mode Scripting / CLI & Automatisation

```bash
# Scan en ligne de commande standard
aiscout --scan

# Lancement direct du Watchdog avec alertes de bureau
aiscout --watch

# Restauration globale des fichiers originaux
aiscout --restore

# Nettoyage définitif des sauvegardes .bak
aiscout --clean-backups

# Liste des 18 règles actives + personnalisées
aiscout --list-rules

# Affichage des valeurs en clair
aiscout --reveal

# Sortie au format JSON pour pipelines automatisés (jq)
aiscout --json | jq '.[] | select(.severity == "CRITIQUE")'

# Exportation automatique d'un rapport complet en Markdown ou JSON
aiscout --export ~/Documents/audit_secrets.md
aiscout --export ~/Documents/audit_secrets.json

# Audit d'un répertoire utilisateur spécifique
aiscout --home-dir /home/autre_utilisateur
```

---

## 🏗️ Architecture Technique

* **Langage** : Python 3.10+ standard pur (`os`, `sys`, `re`, `json`, `unicodedata`, `shutil`, `argparse`, `subprocess`, avec `msvcrt` sous Windows et `termios`/`tty`/`select` sous POSIX).
* **Zéro Dépendance Externe** : Aucun package tiers `pip`. Conçu exclusivement avec la bibliothèque standard Python 3.
* **Systèmes Supportés** : **Linux** (natif Wayland / X11), **Windows 10/11** (natif PowerShell, CMD, Windows Terminal) et **WSL / WSL2**.
* **Système de Notification** : Détection automatique de `notify-send` sous Linux et toasts natifs PowerShell sous Windows.
* **Configuration** : `~/.config/aiscout/rules.json` (ou `%APPDATA%\aiscout\rules.json` sous Windows).
* **Confidentialité absolue** : 100% local, aucun flux réseau sortant, zéro télémétrie.
