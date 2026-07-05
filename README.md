# Init-WindowsServer

Script PowerShell interactif d'initialisation complète d'un serveur **Windows Server
2019/2022/2025** : mises à jour, IP statique, renommage, promotion en contrôleur de domaine,
structure Active Directory selon le modèle **AGDLP** (OU, utilisateurs, ordinateurs, Groupes
Globaux GG, Groupes de Domaine Local GDL), **GPO de durcissement (ANSSI/NIST)**, serveur de
fichiers (partages SMB + ACL NTFS granulaires) et rôles annexes (DHCP, WSUS, RDS, IIS, Hyper-V).

Mono-fichier, sans dépendance externe. Fonctionne sur un OS **anglais comme français**
(identités résolues par SID). Idempotent : relançable sans créer de doublon, avec **reprise
automatique après chaque redémarrage** (fichier d'état `%ProgramData%\InitWindowsServer\state.json`).

## Prérequis

- Windows Server 2019, 2022 ou 2025 (édition Desktop ou Core avec les outils RSAT du serveur)
- Windows PowerShell **5.1** (inclus dans l'OS), compatible PowerShell 7+
- Compte membre du groupe Administrateurs (le script s'auto-élève en UAC)
- Accès Internet uniquement pour l'étape facultative des mises à jour (module PSWindowsUpdate)

## Utilisation

```powershell
# Exécution interactive (Phase 1 sur un serveur membre, Phase 2 sur un contrôleur de domaine)
.\Init-WindowsServer.ps1

# Simulation : affiche ce qui serait fait, sans rien créer
.\Init-WindowsServer.ps1 -WhatIf

# Sans les captures d'écran (Server Core, session sans bureau)
.\Init-WindowsServer.ps1 -NoScreenshots

# Non-interactif, piloté par un fichier de configuration (voir config.sample.psd1)
.\Init-WindowsServer.ps1 -ConfigFile .\config.sample.psd1 -Unattended

# Réinitialisation de ce que le script a créé (voir ci-dessous)
.\Init-WindowsServer.ps1 -Reset
```

Déroulement :

1. **Phase 1** (serveur non promu) : mises à jour Windows, IP statique, renommage,
   fuseau horaire, puis installation AD DS et promotion. Après chaque redémarrage, **relancez le
   script** : il reprend là où il s'était arrêté.
2. **Phase 2** (contrôleur de domaine détecté) : l'existant AD est rechargé, puis le script
   propose la politique de mot de passe du domaine (ANSSI), la création des
   OU/utilisateurs/ordinateurs/GG/GDL, les comptes prestataires à durée limitée, des GPO
   (catalogue de 39 règles de durcissement applicables à la carte ou en pack), des partages
   restreints aux GDL (modèle AGDLP strict) avec énumération basée sur l'accès, la délégation de
   contrôle sur les OU, la préparation Windows LAPS, les rôles optionnels et un audit des accès AD.

À chaque fin de phase, un **rapport d'exécution PDF** est généré (sans besoin d'Office) dans
`C:\Rapports\` par défaut : titre (script/serveur/date), informations clés (IP, domaine,
OU/GG/GDL, partages, rôles), **tableau des comptes créés (Login / Mot de passe en clair / OU)**,
journal des étapes horodaté et **une capture d'écran de fin de chaque grande étape**. Un
récapitulatif `.txt` (sans mots de passe) l'accompagne.

### Génération du PDF (stratégies, dans l'ordre)

Le rapport est produit par la première stratégie disponible, toutes **sans Microsoft Office** :

1. module **PSWritePDF** (s'il est installé) ;
2. bibliothèque **PdfSharp** (déposez `PdfSharp.dll` dans un sous-dossier `lib\` à côté du script
   ou sous `%ProgramData%\InitWindowsServer\lib\`) ;
3. **impression HTML** via le pipeline Windows « Print to PDF » (Edge headless si présent, sinon
   imprimante *Microsoft Print to PDF*) ;
4. **générateur PDF minimal natif intégré** (aucune dépendance, toujours disponible, avec les
   captures d'écran embarquées) ;
5. repli final : rapport **HTML** autonome (captures en base64).

Les captures d'écran (PNG horodatés) sont enregistrées dans `C:\Rapports\captures\` et insérées
sous la section correspondante du PDF. Désactivables via `-NoScreenshots` (ou
`Report.NoScreenshots = $true`). La génération du rapport et des captures est **non bloquante** :
sur Server Core / session sans bureau, l'échec est journalisé et le script continue.

## Mots de passe

Aucun secret n'est codé en dur dans le script. Le mot de passe initial de chaque utilisateur est
généré aléatoirement (`New-RandomPassword`) ou saisi une fois par l'administrateur, au choix,
**affiché en clair** dans le récapitulatif console (tableau `Login | Mot de passe (clair) | OU`)
et le rapport PDF pour la première distribution, puis son **changement est imposé à la première
connexion** (`-ChangePasswordAtLogon`).

> ⚠️ **Avertissement de sécurité**
> - Le rapport PDF **et les captures d'écran** contiennent des mots de passe en clair :
>   stockez `C:\Rapports\` en lieu sûr, **détruisez-le après distribution** des comptes et
>   **excluez-le de tout dépôt Git** (un `.gitignore` est fourni). La réinitialisation « biere »
>   supprime aussi les rapports et captures tracés.
> - Ce script applique des réglages de durcissement (Kerberos AES only, NTLMv1 interdit,
>   blocage USB, désactivation de scripts...) : **testez en environnement de maquette** avant
>   toute production, certaines règles pouvant casser des usages existants (la règle 7.3
>   bloque notamment tous les scripts PowerShell sur les machines ciblées).
> - Outil conçu pour des labs, maquettes et petits environnements : à auditer avant tout usage
>   en production.

## Antivirus (faux positif possible)

La fonction de capture d'écran utilise l'API .NET publique et documentée
`System.Drawing.Graphics.CopyFromScreen`. Sa **coexistence, dans un même fichier**, avec les
réglages de durcissement (LSA, antivirus, USB...) peut être interprétée à tort par certains
antivirus heuristiques (Windows Defender/AMSI notamment) comme un profil de logiciel espion.
Pour éviter ce **faux positif**, le script résout cette méthode **par réflexion** plutôt que par
son nom littéral : la démarche est explicitement commentée dans le code, l'action reste une
simple capture d'écran, journalisée et désactivable via `-NoScreenshots`. Si votre antivirus
bloque malgré tout l'exécution, lancez avec `-NoScreenshots` ou ajoutez une exclusion pour le
script sur votre serveur.

## Durcissement ANSSI et politique de domaine

Le configurateur de GPO propose un catalogue de **39 règles** réparties en 9 catégories, toutes
applicables à la carte ou en pack, et poussées via GPO sur les OU de votre choix :

| Cat. | Thème | Exemples de règles |
|---|---|---|
| 1 | Sécurité du poste | Pare-feu, UAC renforcé, BitLocker (sauvegarde des clés dans l'AD) |
| 2 | Durcissement réseau (ANSSI) | Kerberos AES, NTLMv1 interdit, signature SMB, SMBv1 off, LLMNR off, RDP NLA |
| 3 | Audit et journaux | Ligne de commande dans l'évènement 4688, journalisation/transcription PowerShell |
| 4 | Gestion des postes | Windows LAPS, WSUS, Autorun off, blocage écriture USB |
| 5 | Restrictions utilisateurs | CMD, Gestionnaire des tâches, Panneau de configuration, Regedit |
| 6 | Verrouillage et bannière | Écran de veille sécurisé, bannière légale, dernier identifiant masqué |
| 7 | Réduction surface d'attaque | USBSTOR, stockage amovible, PowerShell RemoteSigned |
| 8 | Protection des identifiants (ANSSI) | WDigest off, protection LSA (RunAsPPL), cache limité, accès anonyme restreint |
| 9 | Défense du poste | SmartScreen, protection PUA Defender, audit avancé forcé |

Les valeurs reposent sur des clés de registre réelles et vérifiées. Les règles à effet de bord
potentiel (protection LSA, RDP NLA, blocage total de PowerShell) portent un avertissement et
restent optionnelles. **Testez en maquette avant toute production.**

En Phase 2, le script propose aussi d'appliquer la **politique de mot de passe et de verrouillage
du domaine** (longueur 12, complexité, historique 24, expiration 90 j, verrouillage 5/15 min),
alignée sur les recommandations ANSSI et sur le module de formation B1-M8. Toutes les valeurs sont
configurables (section `DomainPasswordPolicy`).

Ces mesures reprennent le module « Sécuriser le poste utilisateur et les appareils mobiles »
(comptes locaux, AD/droits réseau AGDLP, chiffrement, durcissement). Points volontairement laissés
en étapes manuelles car hors du périmètre d'un script de GPO : activation effective de BitLocker
(`manage-bde`, choix TPM/PIN), règles AppLocker/WDAC (politique XML), MFA, gestion des appareils
mobiles (MDM).

## Gestion des droits d'accès (module B1-M9)

La Phase 2 intègre plusieurs opérations de gestion fine des droits, dans l'esprit AGDLP et du
moindre privilège :

- **Audit des accès AD** (lecture seule) : membres des groupes à privilèges (Administrateurs,
  Domain/Enterprise/Schema Admins, Opérateurs, etc.), comptes dormants (seuil configurable) et
  comptes à risque (mot de passe non requis ou sans expiration). Les résultats figurent dans le
  rapport PDF. Disponible aussi en mode non-interactif (`AccessAudit`).
- **Énumération basée sur l'accès (ABE)** sur les partages : chaque utilisateur ne voit que ce à
  quoi il a accès (`Set-SmbShare -FolderEnumerationMode AccessBased`).
- **Comptes prestataires à durée limitée** : OU et GDL dédiés, expiration automatique du compte,
  restriction de postes (`LogonWorkstations`) optionnelle, mot de passe généré et imposé au
  premier accès.
- **Délégation de contrôle sur une OU** : délègue à un groupe une tâche précise (réinitialiser les
  mots de passe, gérer les membres de groupe, créer/supprimer des comptes) via `dsacls`, sans
  droits d'administration du domaine. Les ACE déléguées ne sont pas retirées par la
  réinitialisation « biere ».
- **Préparation Windows LAPS côté AD** : extension du schéma (`Update-LapsADSchema`) et délégation
  de lecture des mots de passe (`Set-LapsADReadPasswordPermission`) ; la partie poste s'active via
  la règle GPO 1 (LAPS). Ignorée proprement si les cmdlets Windows LAPS sont absentes.

Restent documentés comme étapes manuelles (non réductibles à un script AD/GPO) : postes
d'administration dédiés (PAW) et « Deny logon » associé, redirection de dossiers, loopback de GPO.

## Réinitialisation « biere »

Le script trace dans `state.json` **chaque objet qu'il crée** (OU, groupes, utilisateurs,
ordinateurs, GPO, liens GPO, partages, dossiers). La fonction de remise à zéro (proposée en fin
de script ou accessible via `-Reset`) supprime **uniquement ces objets tracés**, jamais
l'existant réutilisé.

Protections :

1. saisie **exacte** du mot `biere` (sensible à la casse : toute autre saisie annule) ;
2. récapitulatif détaillé de ce qui va être supprimé, puis **seconde confirmation O/N** ;
3. la suppression des **dossiers** (données !) exige une confirmation supplémentaire séparée ;
4. opération idempotente et tolérante : un objet déjà absent est ignoré sans erreur ; une OU
   contenant des objets non créés par le script est **conservée** et signalée ;
5. la **rétrogradation du contrôleur de domaine n'est JAMAIS incluse** : c'est une option
   distincte, proposée séparément, qui exige la saisie exacte du nom DNS du domaine et une
   dernière confirmation avant `Uninstall-ADDSDomainController`.

Chaque suppression est journalisée et un rapport de réinitialisation est généré.

## Contenu du dépôt

| Fichier | Rôle |
|---|---|
| `Init-WindowsServer.ps1` | Le script (mono-fichier, UTF-8 BOM, PSScriptAnalyzer 0 warning) |
| `config.sample.psd1` | Exemple de configuration pour le mode `-Unattended` |
| `Tests/Init-WindowsServer.Tests.ps1` | Tests Pester v5 des fonctions utilitaires pures |
| `.gitignore` | Ignore les rapports, captures, état local et DLL locales (jamais versionnés) |
| `.gitattributes` | Normalise les fins de ligne (CRLF pour les `.ps1`, LF pour le reste) |
| `CHANGELOG.md` | Historique des corrections et évolutions |
| `LICENSE` | Licence MIT |

> Le `.gitignore` fourni ignore les rapports (`Init-WindowsServer_*`, `*.pdf`, `captures/`,
> `Rapports/`) pour éviter tout commit accidentel de mots de passe. **Ne stockez jamais
> `C:\Rapports\` dans Git.**

## Tests

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
Invoke-Pester -Path .\Tests
```

Les tests dot-sourcent le script (le point d'entrée est protégé) et couvrent les validateurs,
le générateur de mots de passe, l'échappement XML, le mapping NTFS vers SMB, le fichier d'état v2, le
retour à la ligne du PDF et la génération du rapport PDF (générateur natif + repli HTML).

## Licence

[MIT](LICENSE) : utilisez, modifiez, partagez. Et si ce script vous a sauvé la vie...
*payez une bière à Quentin et Max à l'occasion !* 🍺
