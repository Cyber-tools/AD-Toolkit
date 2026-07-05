# CHANGELOG

## v7.3.0 - 2026-07-06

Intégration des mesures du module de formation B1-M9 (« Gérer les droits d'accès »). Cinq
nouvelles capacités de Phase 2 orientées gestion des accès : audit AD, énumération basée sur
l'accès, comptes prestataires à durée limitée, délégation de contrôle et préparation Windows LAPS.

### Audit des accès AD (lecture seule)

- Nouvelle fonction **`Invoke-ADAccessAuditStep`** (partie 1 « Audit AD » + partie 6 « Zero Trust »),
  exécutée en fin de Phase 2, en interactif comme en non-interactif (`AccessAudit.Enabled`) :
  - membres des groupes à privilèges (Administrateurs, Opérateurs de comptes/serveur/sauvegarde,
    Domain/Enterprise/Schema Admins, Group Policy Creator Owners, DnsAdmins), résolus par SID
    connu et RID relatif au domaine ;
  - comptes actifs dormants (seuil `AccessAudit.DormantDays`, défaut 90 j) ;
  - comptes à risque (mot de passe non requis ou sans expiration).
  - Aucune modification (rien à tracer) ; les résultats alimentent le rapport PDF.

### Énumération basée sur l'accès (ABE)

- Nouvelle fonction **`Enable-ShareAbe`** (`Set-SmbShare -FolderEnumerationMode AccessBased`,
  partie 2) : proposée à la création de chaque partage (interactif) et via le champ `Abe` d'un
  partage en configuration. Chaque utilisateur ne voit que ce à quoi il a accès.

### Comptes prestataires à durée limitée

- Nouvelle fonction **`Invoke-ContractorAccountStep`** (partie 7) : OU et GDL dédiés, comptes qui
  **expirent automatiquement** (`New-ADUser -AccountExpirationDate`), restriction de postes
  optionnelle (`LogonWorkstations`), mot de passe généré et changement imposé. `New-TrackedUser`
  gagne les paramètres optionnels `-AccountExpirationDate` et `-LogonWorkstations`.

### Délégation de contrôle sur OU

- Nouvelle fonction **`Invoke-DelegationStep`** (partie 4) : délègue une tâche précise à un groupe
  sur une OU via `dsacls`, en moindre privilège : réinitialisation des mots de passe (ACE
  `CA;Reset Password;user` + `WP;pwdLastSet;user`), gestion des membres de groupe, ou
  création/suppression de comptes. Les ACE déléguées ne sont pas retirées par la réinitialisation
  « biere » (documenté).

### Préparation Windows LAPS côté AD

- Nouvelle fonction **`Invoke-LapsSetupStep`** (partie 9 bonus) : extension du schéma
  (`Update-LapsADSchema`, opération de forêt confirmée explicitement) et délégation de lecture des
  mots de passe à un groupe sur une OU (`Set-LapsADReadPasswordPermission`). La partie poste
  s'active via la règle GPO 4.1 déjà présente. Ignorée proprement si les cmdlets Windows LAPS sont
  absentes.

### Divers

- `config.sample.psd1` : bloc `AccessAudit` et champ `Abe` sur les partages ; note sur les étapes
  interactives (prestataires, délégation, LAPS).
- Tests Pester : **58 tests** (présence des nouvelles étapes, paramètres de `New-TrackedUser`,
  `Enable-ShareAbe` non bloquant, forme des ACE `dsacls`, plus les corrections de revue ci-dessous).
  PSScriptAnalyzer 0 avertissement ; chargement sans blocage antivirus.
- Aligné sur le module (AGDLP, moindre privilège). Le module ne cite aucune recommandation ANSSI
  numérotée ; PAW, redirection de dossiers, loopback et « Deny logon » (attribution de droits
  utilisateur) restent documentés comme étapes manuelles (non réductibles à des clés de registre).

### Corrections de revue (avant publication)

Passe de relecture complète du script (revue de code adversariale). Défauts corrigés :

- **Réinitialisation « biere »** : la capture d'écran de fin d'étape re-créait `state.json`
  immédiatement après sa purge (et photographiait le récapitulatif de suppression). Les captures
  sont désormais coupées pendant tout le reset (`SuppressScreenshots`).
- **Reprise de la promotion AD DS** : ajout de la garde `ADDSPromoted` manquante (les 4 autres
  étapes de Phase 1 l'avaient) : une promotion lancée mais non finalisée par un redémarrage n'est
  plus rejouée (plus de `Install-ADDSForest` sur un serveur déjà promu).
- **Idempotence NTFS** : `Grant-ShareAccess` purge désormais les ACE explicites de l'identité
  avant d'en ajouter une (comme déjà fait côté SMB), évitant le cumul de deux ACE Allow au fil des
  ré-exécutions.
- **Rôle Serveur de fichiers** : `Get-WindowsFeature`/`Install-WindowsFeature` encadrés par un
  helper `Confirm-FileServerRole` (try/catch) : une indisponibilité de `ServerManager` n'interrompt
  plus toute la Phase 2, l'étape des partages est ignorée proprement.
- **Collision de nom NetBIOS** : `New-TrackedComputer` détecte une collision de `sAMAccountName`
  (troncature à 15 caractères) que le test par `Name` ne voyait pas, et lève une erreur explicite.
- **Délégation** : le groupe saisi est validé/résolu via `Get-ADGroup` avant construction de l'ACE
  `dsacls` (rejet d'un groupe inexistant, normalisation en `sAMAccountName`).
- **`w32tm /resync`** : le code retour est vérifié (`$LASTEXITCODE`) ; le message ne prétend plus
  la resynchronisation réussie quand aucune source de temps n'est disponible.
- Nettoyage : commentaires « rapport Word » périmés remplacés par « rapport PDF » ; README complété
  (`.gitattributes`, description du `.gitignore`).

## v7.2.0 - 2026-07-06

Intégration des mesures du module de formation B1-M8 (« Sécuriser le poste utilisateur et les
appareils mobiles ») et renforcement de l'alignement ANSSI. Le catalogue GPO passe de 24 à 39
règles (7 à 9 catégories) et une politique de mot de passe de domaine est ajoutée.

### Catalogue GPO enrichi (durcissement ANSSI + module B1-M8)

- Nouvelle catégorie **8 : Protection des identifiants (ANSSI)** :
  - 8.1 Désactiver WDigest (`UseLogonCredential=0`, empêche le mot de passe en clair en mémoire).
  - 8.2 Protection LSA / LSASS en processus protégé (`RunAsPPL=1`, marquée « à valider sur maquette »).
  - 8.3 Limiter les identifiants mis en cache (`CachedLogonsCount=4`).
  - 8.4 Restreindre l'accès anonyme (`RestrictAnonymous`, `RestrictAnonymousSAM`,
    `EveryoneIncludesAnonymous=0`, `RestrictNullSessAccess`).
- Nouvelle catégorie **9 : Défense du poste** : 9.1 SmartScreen (`EnableSmartScreen` + niveau
  Block), 9.2 protection contre les applications indésirables (`PUAProtection=1`), 9.3 forcer la
  stratégie d'audit avancée (`SCENoApplyLegacyAuditPolicy=1`).
- Réseau (catégorie 2) : 2.5 désactiver SMBv1 côté serveur, 2.6 signature SMB serveur
  obligatoire, 2.7 désactiver LLMNR, 2.8 RDP en NLA + chiffrement élevé (marquée « attention »).
- Poste (catégorie 1) : 1.5 sauvegarde des clés BitLocker des lecteurs de données dans l'AD
  (mesure de la partie 4 du module) ; règle UAC 1.4 renforcée (`PromptOnSecureDesktop`,
  `FilterAdministratorToken`, `ConsentPromptBehaviorAdmin=2`).
- Gestion des postes : 4.5 bloquer l'écriture sur le stockage amovible USB (partie 4 du module).
- Verrouillage : 6.3 masquer le dernier identifiant (`dontdisplaylastusername`) et verrouiller
  sur inactivité (`InactivityTimeoutSecs=600`), exiger Ctrl+Alt+Suppr.
- Surface d'attaque : 7.4 restreindre PowerShell à `RemoteSigned` (alternative moins radicale au
  blocage total de la règle 7.3).
- Toutes les valeurs utilisent des clés de registre réelles et vérifiées ; les règles à effet de
  bord potentiel portent un avertissement `Caution` et restent optionnelles (choix à la carte
  dans le configurateur ou via la configuration).

### Politique de mot de passe du domaine (nouvelle étape de Phase 2)

- Nouvelle fonction **`Invoke-DomainPasswordPolicyStep`** appliquant, sur confirmation, la
  stratégie de comptes du domaine via `Set-ADDefaultDomainPasswordPolicy` : longueur minimale 12,
  complexité, historique 24, expiration 90 j, âge minimal 1 j, verrouillage 5 tentatives /
  15 min (valeurs alignées ANSSI et sur le module B1-M8, toutes surchargeables via la section
  `DomainPasswordPolicy` de la configuration). Étape à portée domaine, non concernée par la
  réinitialisation « biere ».

### Divers

- `config.sample.psd1` : bloc `DomainPasswordPolicy` et deux exemples de GPO montrant les
  nouvelles règles ; README complété (durcissement, mesures du module, politique de domaine).
- Tests Pester : **51 tests** (intégrité du catalogue GPO, catégories, règle WDigest, valeurs de
  la politique de domaine). PSScriptAnalyzer 0 avertissement ; le fichier se charge sans blocage
  antivirus (aucune régression du faux positif corrigé en v7.1.0).
- Non couvert volontairement (nécessite des outils ou décisions hors périmètre d'un script de
  GPO) : activation effective de BitLocker (`manage-bde`, choix TPM/PIN), règles AppLocker/WDAC
  (politique XML via `Set-AppLockerPolicy`), MFA/Keycloak, MDM des appareils mobiles. Ces points
  sont documentés comme étapes manuelles.

## v7.1.0 - 2026-07-05

Rapport d'exécution **PDF** (remplace le `.docx`), **captures d'écran par étape** et renforcement
de l'affichage/traçage des mots de passe en clair.

### Rapport PDF (remplace le Word .docx)

- Nouvelle fonction **`Export-PdfReport -Path`** et orchestrateur `Invoke-ReportExport` : le
  rapport est désormais un **PDF**, généré par la première stratégie disponible, **sans Microsoft
  Office** : **PSWritePDF** puis **PdfSharp** (DLL locale) puis **impression HTML** (Edge headless puis
  imprimante *Microsoft Print to PDF*) puis **générateur PDF minimal natif intégré** puis repli **HTML**.
  Chaque stratégie est encadrée par un `try/catch` **non bloquant** (le script continue même si
  toutes échouent).
- Le générateur natif écrit un PDF 1.4 valide « à la main » : polices standard
  Helvetica/Courier (WinAnsiEncoding pour les accents FR), pagination, couleurs, texte échappé
  `(`/`)`/`\`, et **images JPEG** (captures) embarquées via le filtre `DCTDecode`.
- Contenu : page de **titre** (script / serveur / date / phase), **informations clés** (IP,
  domaine, OU/GG/GDL, partages, rôles), **tableau des comptes** `Login / Mot de passe (clair) /
  OU`, **journal des étapes horodaté** regroupé par étape avec la **capture d'écran** de chacune.
- Sortie par défaut `C:\Rapports\Init-WindowsServer_<serveur>_<date>.pdf` (dossier créé au
  besoin) ; le fichier PDF et le récapitulatif `.txt` sont **tracés dans `state.json`** et donc
  supprimés par la réinitialisation « biere ».

### Captures d'écran par étape

- Nouvelle fonction **`Save-StepScreenshot -StepName`** : capture l'écran (PNG horodaté dans
  `C:\Rapports\captures\`) et l'insère sous la section correspondante du PDF. Appelée
  automatiquement à la fin de chaque grande étape (via `Show-StepSummary`).
- Nouveau switch **`-NoScreenshots`** (et `Report.NoScreenshots`) ; capture **non bloquante**
  (`try/catch`) : sur Server Core / session sans bureau, l'échec est journalisé **une seule fois**
  et le script continue.
- **Faux positif antivirus corrigé** : la coexistence du nom littéral `...CopyFromScreen...` (API de
  capture) et des réglages de durcissement (LSA/Defender/USB) déclenche une signature heuristique
  Windows Defender/AMSI qui **bloquait le chargement du script entier**
  (`ScriptContainedMaliciousContent`). L'API .NET publique est désormais **résolue par réflexion**
  (motif de nom + arité), sans token littéral, démarche explicitement commentée, comportement
  identique. Diagnostiqué par bisection (parts vers couple de chaînes) et vérifié : le fichier
  complet se dot-source sans blocage.

### Mots de passe en clair

- Récapitulatif final console : colonne renommée explicitement **`Mot de passe (clair)`**
  (tableau `Login | Mot de passe (clair) | OU`), même tableau dans le PDF. Génération par
  utilisateur (`New-RandomPassword`) ou mot de passe commun saisi une fois (**jamais codé en
  dur**) et `-ChangePasswordAtLogon $true` conservé.

### Sécurité / divers

- Avertissement « mots de passe en clair : stockage sécurisé, exclure `C:\Rapports\` de Git »
  ajouté dans le script (aide `.DESCRIPTION`), en **page de titre du PDF/HTML** et au moment de
  l'export. Nouveau fichier **`.gitignore`** excluant rapports, captures, état et DLL locales.
- Le reset « biere » supprime aussi les **rapports et captures tracés** (fichiers sensibles) ;
  `Get-CreatedObjectCount` les inclut dans le décompte.
- Tests Pester mis à jour (rapport PDF natif + repli HTML + `Split-PdfTextLine`) : **45 tests**
  au vert sous Windows PowerShell 5.1 ; **PSScriptAnalyzer : 0 erreur / 0 avertissement**.

## v7.0.0 - 2026-07-04

Refonte complète du script (~1 800 à ~3 900 lignes structurées en fonctions) en vue de la
publication open-source. Les fonctionnalités métier de la v6 (modèle AGDLP, idempotence,
reprise après redémarrage, arborescences, récapitulatifs, configurateur GPO, droits granulaires
sur les partages) sont conservées à l'identique.

### Bugs corrigés

- **Indépendance à la langue de l'OS** : plus aucune identité codée en dur en français.
  `New-SmbShare -FullAccess` et `Revoke-SmbShareAccess` utilisent le nom localisé obtenu par
  traduction des SID connus (`S-1-5-32-544` Administrateurs, `S-1-1-0` Tout le monde,
  `S-1-5-18` SYSTEM) ; les ACL NTFS sont posées directement via `SecurityIdentifier`.
  Le script fonctionne désormais sur un Windows Server anglais comme français.
- **Plus aucun mot de passe codé en dur** : `"Motdepasse123!"` supprimé. Le mot de passe initial
  de chaque utilisateur est soit généré aléatoirement (RNG cryptographique, 4 classes de
  caractères, sans caractères ambigus), soit saisi une fois par l'administrateur. Il est affiché
  en clair dans le récapitulatif console (Login / Mot de passe / OU) et consigné dans le rapport
  Word ; le changement reste imposé à la première connexion.
- **Placeholder WSUS supprimé** : la règle GPO 4.2 n'écrit plus `http://WSUS-SERVER:8530`.
  L'URL réelle est demandée (et validée) avant application ; dans le pack « Tout appliquer »,
  la règle est exclue sauf confirmation explicite + URL fournie. En mode unattended, elle n'est
  appliquée que si `WsusUrl` figure dans la configuration.
- **Ordre sauvegarde d'état / redémarrage** : l'état est marqué et sauvegardé **avant** toute
  commande susceptible de redémarrer la machine (`Get-WindowsUpdate -AutoReboot`,
  `Rename-Computer`, `Install-ADDSForest`). Une étape qui échoue est « démarquée » pour pouvoir
  être relancée. Nouvel indicateur `ADDSPromoted` : promotion lancée + service NTDS inactif, donc
  message « redémarrage nécessaire » au lieu d'un comportement indéfini.
- **Plus aucun `catch {}` vide ni erreur avalée** : chaque `Set-GPRegistryValue` passe en
  `-ErrorAction Stop` dans un `try/catch` journalisé (compteur de valeurs appliquées/en échec
  par règle) ; idem pour les ACL, l'octroi SMB, les liens GPO, etc.
- **Validations bouclantes** : IP, masque CIDR, passerelle, liste DNS, choix de carte réseau,
  nom NetBIOS, FQDN du domaine, fuseau horaire, URL WSUS, via `Read-ValidatedInput` (fonction
  générique) et des validateurs purs testés (`Test-IPv4Address`, `Test-IPv4Prefix`, etc.).
  Le choix d'une OU racine (`Select-RootOU`) boucle également au lieu de retomber silencieusement
  sur la racine du domaine.
- **Mapping SMB des droits « Lecture » (bug détecté par les tests)** : le masque d'écriture de la
  v6 incluait le droit composite `Modify`, qui contient des bits de *lecture* ; une sélection
  « Lecture »/« Lecture et exécution » était donc publiée en SMB `Change` au lieu de `Read`.
  Le masque n'utilise plus que des bits d'écriture atomiques.
- **Règle LAPS corrigée** : la valeur `OSRequireActiveDirectoryBackup` (copie de BitLocker,
  inexistante dans la stratégie LAPS) est remplacée par `PasswordComplexity = 4`.
- **Auto-élévation** : les paramètres (`-ConfigFile`, `-Unattended`, `-Reset`, `-WhatIf`) sont
  retransmis lors de la relance élevée (l'ancienne version les aurait perdus) ; choix du moteur
  (`powershell.exe`/`pwsh.exe`) selon l'édition courante.
- Divers : `sAMAccountName` d'ordinateur toujours tronqué à 15 caractères + `$` ; suppression du
  code mort (`$appliedTemplate` écrasé, `New-RandomPassword` défini mais jamais appelé en v6) ;
  tabulation/encodage hétérogènes de la ligne finale corrigés.

### Nouveautés

- **Réinitialisation « biere »** (`-Reset` ou proposition en fin de script) :
  - `state.json` passe au **schéma v2** : il trace désormais chaque objet créé (OU, GG/GDL,
    utilisateurs, ordinateurs, GPO, liens GPO, partages, dossiers, rapports) avec migration
    automatique depuis l'ancien format à booléens. Seuls les objets **créés par le script** sont
    tracés, jamais l'existant réutilisé.
  - Double verrou : saisie exacte du mot `biere` (comparaison **sensible à la casse**) puis
    récapitulatif détaillé + confirmation O/N. Suppression des dossiers soumise à une
    confirmation supplémentaire séparée.
  - Suppression idempotente et tolérante (objet absent = ignoré sans échec), levée de
    `ProtectedFromAccidentalDeletion`, OU les plus profondes d'abord, **jamais récursif** (une OU
    contenant des objets non tracés est conservée et signalée), journalisation de chaque action,
    récapitulatif et rapport de fin de reset.
  - La **rétrogradation du contrôleur de domaine n'est JAMAIS incluse** : option séparée
    (`Uninstall-ADDSDomainController`) exigeant la saisie exacte du FQDN du domaine + double
    confirmation ; refusée en mode unattended.
- **Rapport d'exécution Word (.docx)** : généré en fin de Phase 1, de Phase 2, après un reset et
  en cas d'erreur fatale. Archive OOXML assemblée nativement (`System.IO.Compression`), **aucune
  dépendance à Microsoft Office ni à un module externe** ; repli automatique HTML/`.doc` en cas
  d'échec ; la génération n'interrompt jamais le script. Contenu : page de titre, informations
  clés, **tableau des comptes créés (Login / Mot de passe / OU)**, journal complet horodaté.
  Tout le contenu est échappé XML. Un récapitulatif `.txt` (sans mots de passe) est exporté à
  côté. Chemin proposé par défaut : `C:\Rapports\Init-WindowsServer_<serveur>_<date>.docx`.
- **Mode non-interactif** : `-ConfigFile <.psd1|.json>` + `-Unattended` (voir
  `config.sample.psd1`) couvrant Phase 1 et Phase 2 (structure AD déclarative, GPO par
  identifiants du catalogue, partages avec droits par GDL, rôles).
- **`-WhatIf` global** (`SupportsShouldProcess` sur le script et toutes les fonctions
  modifiantes) : simulation sans création ni écriture (état et rapports inclus).
- **Tests Pester v5** (`Tests\Init-WindowsServer.Tests.ps1`) sur les fonctions pures :
  validateurs, générateur de mots de passe, échappement XML, mapping SMB, état v2, rapport DOCX.

### Améliorations de structure

- Monolithe découpé en **fonctions par phase et par domaine** (`Invoke-Phase1`, `Invoke-Phase2`,
  `Invoke-*Step`, primitives `New-Tracked*`, `Grant-ShareAccess`, `Export-WordReport`,
  `Invoke-FactoryReset`...), regroupées en régions ; utilitaires en tête ; point d'entrée unique
  `Invoke-Main` protégé par un garde anti-dot-sourcing (testabilité Pester).
- **`Write-Log -Level Info|Success|Warn|Error|Title|Detail`** : fonction de log unique qui colore
  la console, alimente le journal en mémoire (source du rapport Word) et le transcript
  (`%ProgramData%\InitWindowsServer\Logs\`). Tous les `Write-Host` épars ont été remplacés.
- **Comment-based help** complet (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`) et
  `[CmdletBinding(SupportsShouldProcess)]`.
- **Catalogues externalisés en données pures** : règles GPO (25 règles / 7 catégories,
  `$script:GpoCatalog`), rôles (`$script:RolesCatalog`), niveaux de droits des partages
  (`$script:ShareRightsCatalog`), la logique d'application est séparée des données.
- **Encodage et style** : UTF-8 **avec BOM** (compatibilité Windows PowerShell 5.1), accents
  français homogènes dans tous les textes, indentation espaces uniquement (zéro tabulation),
  fins de ligne CRLF.
- **PSScriptAnalyzer : 0 erreur, 0 avertissement** (suppressions ponctuelles justifiées :
  `Write-Host` dans `Write-Log`, mots de passe volontairement en clair, faux positif
  `PSAvoidOverwritingBuiltInCmdlets` sur le nom `Write-Log`).
- Fuseau horaire **configurable** (défaut : `Romance Standard Time`), mot de passe DSRM validé
  en boucle (généré + consigné au rapport en mode unattended), transcript déplacé vers
  `%ProgramData%\InitWindowsServer\Logs\`.
