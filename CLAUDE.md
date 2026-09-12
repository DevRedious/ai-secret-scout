# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Vue d'ensemble

AI Secret Scout (`aiscout`) détecte, puis caviarde, les secrets restés en clair dans les historiques
des assistants de code IA (`~/.claude`, `~/.gemini`, `~/.codex`, `~/.copilot`, `~/.cursor`, Aider…).
Il est distribué comme paquet npm, mais **tout le moteur est un unique script Python**
(`ai_secret_scout.py`, stdlib uniquement, Python ≥ 3.10). Le JavaScript de `bin/` ne sert qu'à lancer ce script.

Dépôt public : https://github.com/DevRedious/ai-secret-scout — paquet npm `ai-secret-scout` (compte `devredious`).
Il n'existe aucune suite de tests.

## Commandes

```bash
python3 ai_secret_scout.py                # TUI plein écran (équivaut à `npm start` / `aiscout`)
python3 ai_secret_scout.py --scan         # scan puis tableau interactif
python3 ai_secret_scout.py --json         # scan headless, JSON sur stdout
python3 ai_secret_scout.py --list-rules   # règles intégrées + personnalisées
python3 ai_secret_scout.py --home-dir DIR # scanne un autre $HOME (utile pour tester)
python3 -m py_compile ai_secret_scout.py  # vérification syntaxique minimale

npm run lint      # biome lint . (ne couvre que le JS de bin/)
npm run check     # biome check --write .
npm run ci        # biome ci . (indentation par tabulations, imports `node:`)
npm publish --dry-run   # vérifier le contenu du tarball avant publication
```

**Attention en testant** : sans `--home-dir`, le scan lit les vrais historiques de l'utilisateur, et
`--json` / `--reveal` affichent les secrets en clair. Le caviardage (TUI `[6]` ou `[C]`) et
`--restore` / `--clean-backups` **modifient réellement** les fichiers sous `~`. Pour tester, pointer
`--home-dir` vers un faux home contenant par exemple `.claude/projects/-x/session.jsonl`.
Au premier lancement, `load_custom_rules()` crée `~/.config/aiscout/rules.json`
(`%APPDATA%\aiscout` sous Windows).

## Architecture

- `bin/aiscout.js` : appelle `runCheck()` de `bin/check-environment.js` (Node ≥ 16, recherche d'un
  Python ≥ 3.10 parmi `python3`/`python`/`py`), puis lance `ai_secret_scout.py` avec les arguments
  transmis tels quels. `check-environment.js --postinstall` sert de hook `postinstall` npm et ne fait qu'avertir.
- `ai_secret_scout.py`, de haut en bas :
  1. **i18n** : `CURRENT_LANG`, `t(key)`, `I18N_STRINGS`, et les tables de traduction FR→EN
     `SEV_TRANSLATIONS`, `RULE_I18N`, `USAGE_CONTEXT_I18N`.
  2. **`PATTERNS`** (règles intégrées) + `load_custom_rules()`, qui fusionne `rules.json` en suffixant les noms par ` [CUSTOM]`.
  3. Heuristiques (`calculate_entropy`, `count_character_classes`, `PLACEHOLDER_KEYWORDS`,
     `COMMON_WORDS_FR_EN`), `read_key()` multiplateforme (`msvcrt` / `termios`+`select`), notifications bureau.
  4. **`Finding`** : un secret trouvé ; `to_dict()` alimente le JSON et les exports.
  5. **`ScoutEngine`** : chemins ciblés (`get_target_directories`), attribution outil/projet
     (`identify_tool`, `resolve_project`, qui lit `cwd` dans les JSONL Claude), filtre anti-faux-positifs
     `is_valid_secret`, `scan`, `scan_single_file` (watchdog), `redact_secret`, gestion des `.bak`.
  6. **`ScoutTUI`** : écran alterné ANSI, hub, tableau, fiche détaillée, exports Markdown/JSON, écran de restauration, watchdog.
  7. `main()` : argparse ; chaque drapeau CLI appelle directement une méthode du moteur ou du TUI.

### Pièges à connaître

- **Les clés internes sont en français.** Sévérités `CRITIQUE` / `ÉLEVÉ` / `MOYEN`, noms de catégories
  (`"Clé Privée (SSH / RSA / ECC)"`, `"Mot de passe en clair dans le Prompt"`…) et contextes d'usage
  sont stockés en FR, puis traduits à l'affichage. `is_valid_secret` filtre sur des **sous-chaînes de ces
  noms** (`"Clé Privée"`, `"Prompt"`, `"CLI"`, `"commande"`, `"sensible"`) et le tri de `scan()` compare
  aux sévérités FR. Renommer une catégorie désactive silencieusement ses heuristiques ; toute nouvelle
  règle demande aussi une entrée dans `RULE_I18N["en"]`.
- **La logique de scan existe en trois exemplaires** : `scan()` via ripgrep (un `rg` par règle, puis
  nouveau passage `re.finditer` en Python sur chaque ligne trouvée), `scan()` en repli pur Python quand
  `rg` est absent (seulement `.jsonl`/`.json`/`.md`), et `scan_single_file()`. Une modification du
  matching ou de la construction des `Finding` doit être reportée dans les trois. Les regex doivent donc
  rester compatibles à la fois avec ripgrep et avec `re`. Quand une regex comporte un groupe, c'est `group(1)` qui est retenu comme secret.
- **Anti-auto-détection** : les chemins contenant `ai_secret_scout` sont ignorés, tout comme les lignes
  contenant `[REDACTED_BY_AISCOUT]`, `AI SECRET SCOUT` ou `FICHE DÉTAILLÉE DU SECRET`. Changer ces libellés
  (dans les exports par exemple) peut faire remonter les rapports de l'outil comme des fuites.
- **Caviardage** : `redact_secret` remplace *toutes* les occurrences de la valeur dans le fichier, pas
  seulement la ligne. Le `.bak` n'est créé qu'au premier caviardage, il conserve donc l'original.
  `restore_backup` copie `X.bak` sur `X` puis supprime le `.bak`. Les `.bak` sont exclus des scans.

## Maintenance

- La version figure dans `package.json`, dans `VERSION` (`ai_secret_scout.py`) et dans le titre et les
  captures des deux README (`AISCOUT vX.Y.Z`), à garder synchronisés. Une version déjà publiée sur npm ne peut pas être republiée.
- La documentation est bilingue : `README.md` (EN) et `README.fr.md` (FR) se modifient ensemble.
  Les libellés visibles se modifient dans les deux langues de `I18N_STRINGS`.
- Contrainte produit : **aucune dépendance** Python externe, aucun trafic réseau, compatibilité
  Linux / Windows natif / WSL (garder les branches `IS_WINDOWS`).
- Le paquet npm publie uniquement `bin/`, `ai_secret_scout.py` et les deux README (champ `files` + `.npmignore`).
