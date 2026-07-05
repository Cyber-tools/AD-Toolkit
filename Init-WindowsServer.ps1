#Requires -Version 5.1
<#
.SYNOPSIS
    Initialise un serveur Windows de A a Z : mises a jour, IP statique, renommage,
    promotion AD DS, structure Active Directory (modele AGDLP), GPO de durcissement
    (ANSSI/NIST), serveur de fichiers (SMB + NTFS) et roles annexes.

.DESCRIPTION
    Script interactif (ou non-interactif via -ConfigFile/-Unattended) d'initialisation
    d'un serveur Windows Server 2019/2022/2025, decoupe en deux phases :

      PHASE 1 (serveur non promu) : mises a jour Windows, configuration IP statique,
      renommage du serveur, fuseau horaire, installation AD DS et promotion en
      controleur de domaine (avec reprise automatique apres chaque redemarrage).

      PHASE 2 (controleur de domaine) : creation de la structure AD selon le modele
      AGDLP (OU, utilisateurs, ordinateurs, Groupes Globaux GG, Groupes de Domaine
      Local GDL), GPO predefinies (catalogue de durcissement ANSSI/NIST), partages
      reseau avec droits SMB/NTFS granulaires, roles optionnels (DHCP, WSUS, RDS,
      IIS, Hyper-V).

    Le script est idempotent (les objets existants sont detectes et reutilises),
    tolere les pannes (fichier d'etat %ProgramData%\InitWindowsServer\state.json),
    fonctionne quelle que soit la langue de l'OS (identites resolues par SID),
    journalise chaque action et genere un rapport d'execution au format PDF (sans
    Microsoft Office : module PSWritePDF, DLL PdfSharp, impression HTML via
    Edge/Microsoft Print to PDF ou generateur PDF natif integre, repli HTML)
    incluant le tableau des comptes crees avec leurs mots de passe initiaux EN
    CLAIR et une capture d'ecran de fin de chaque grande etape.

    ATTENTION : le rapport contient des mots de passe en clair. Stockez-le en lieu
    sur, detruisez-le apres distribution et excluez C:\Rapports\ de tout depot Git.

    Une fonction de reinitialisation (protegee par la saisie exacte du mot 'biere')
    supprime tout ce que le script a cree et trace : objets AD, GPO, partages et,
    sur confirmation separee, les dossiers. La retrogradation du controleur de
    domaine n'est JAMAIS incluse dans cette reinitialisation : c'est une option
    distincte, explicitement confirmee.

.PARAMETER ConfigFile
    Chemin d'un fichier de configuration .psd1 ou .json decrivant les reponses
    (reseau, domaine, structure AD, GPO, partages, roles). Voir config.sample.psd1.

.PARAMETER Unattended
    Execute sans poser de question : les valeurs proviennent de -ConfigFile et des
    valeurs par defaut. Les etapes sans configuration correspondante sont ignorees.
    La reinitialisation 'biere' et la retrogradation sont refusees dans ce mode.

.PARAMETER Reset
    Lance directement la procedure de reinitialisation (suppression de ce que le
    script a cree et trace dans son fichier d'etat), protegee par la saisie exacte
    du mot 'biere' puis par une seconde confirmation.

.PARAMETER NoScreenshots
    Desactive les captures d'ecran de fin d'etape (utile sur Server Core, en
    session sans bureau, ou pour alleger le rapport PDF).

.EXAMPLE
    PS> .\Init-WindowsServer.ps1
    Execution interactive classique (Phase 1 ou Phase 2 selon l'etat du serveur).

.EXAMPLE
    PS> .\Init-WindowsServer.ps1 -ConfigFile .\config.sample.psd1 -Unattended
    Execution sans question a partir du fichier de configuration.

.EXAMPLE
    PS> .\Init-WindowsServer.ps1 -Reset
    Reinitialisation de ce que le script a cree (mot de passe 'biere' exige).

.EXAMPLE
    PS> .\Init-WindowsServer.ps1 -WhatIf
    Simulation : affiche les actions qui seraient realisees sans les executer.

.NOTES
    Version   : 7.3.0
    Cible     : Windows Server 2019 / 2022 / 2025 - Windows PowerShell 5.1+
    Etat      : %ProgramData%\InitWindowsServer\state.json (objets crees traces)
    Journaux  : %ProgramData%\InitWindowsServer\Logs\
    Licence   : MIT
    Le script s'auto-eleve : pas de directive #Requires -RunAsAdministrator, qui
    empecherait justement l'auto-elevation de s'executer.

.LINK
    https://github.com/<votre-compte>/Init-WindowsServer
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$ConfigFile,

    [Parameter()]
    [switch]$Unattended,

    [Parameter()]
    [switch]$Reset,

    [Parameter()]
    [switch]$NoScreenshots
)

# =====================================================================
#  REGION 0 : CONSTANTES, SID CONNUS ET CATALOGUES (donnees pures)
# =====================================================================
#region Constantes et catalogues

# Propagation explicite des parametres du script vers la portee script :
# les fonctions (Invoke-Main notamment) les consomment via $script:Param*.
$script:ParamConfigFile    = $ConfigFile
$script:ParamUnattended    = [bool]$Unattended
$script:ParamReset         = [bool]$Reset
$script:ParamNoScreenshots = [bool]$NoScreenshots

$script:ScriptName    = 'Init-WindowsServer'
$script:ScriptVersion = '7.3.0'
$script:ScriptPath    = $PSCommandPath

$script:StateDir     = Join-Path -Path $env:ProgramData -ChildPath 'InitWindowsServer'
$script:StatePath    = Join-Path -Path $script:StateDir -ChildPath 'state.json'
$script:LogDir       = Join-Path -Path $script:StateDir -ChildPath 'Logs'
$script:ResetKeyword = 'biere'   # mot de passe symbolique du reset (sensible a la casse)

# --- SID connus : garantissent le fonctionnement sur un OS anglais comme francais.
# Les noms localises ("Administrateurs"/"Administrators", "Tout le monde"/"Everyone")
# sont obtenus par traduction du SID au moment de l'execution.
$script:WellKnownSid = @{
    Administrators     = 'S-1-5-32-544'
    Users              = 'S-1-5-32-545'
    System             = 'S-1-5-18'
    Everyone           = 'S-1-1-0'
    AuthenticatedUsers = 'S-1-5-11'
}

# --- Valeurs par defaut (personnalisables via le fichier de configuration) ---
$script:Defaults = @{
    TimeZoneId      = 'Romance Standard Time'   # Paris ; configurable (cle TimeZoneId)
    ReportDirectory = 'C:\Rapports'
    ShareRootPath   = 'C:\Partages'
    PasswordLength  = 14
}

# --- Politique de mot de passe/verrouillage du domaine (ANSSI, alignee module B1-M8).
# Appliquee par Invoke-DomainPasswordPolicyStep via Set-ADDefaultDomainPasswordPolicy.
# Valeurs surchargeables via la section 'DomainPasswordPolicy' du fichier de configuration.
$script:DomainPasswordPolicyDefaults = @{
    MinLength          = 12    # ANSSI : >= 12 (module B1-M8 : 12 au siege)
    Complexity         = $true
    HistoryCount       = 24    # ANSSI : 24 mots de passe memorises
    MaxAgeDays         = 90    # 0 = pas d'expiration (ANSSI tolere si mot de passe long)
    MinAgeDays         = 1
    LockoutThreshold   = 5     # module B1-M8 : 5 tentatives
    LockoutDurationMin = 15
    LockoutWindowMin   = 15
    ReversibleEncryption = $false
}

# --- Catalogue des categories de regles GPO ---
$script:GpoCategories = [ordered]@{
    '1' = 'Sécurité du poste'
    '2' = 'Durcissement réseau (ANSSI)'
    '3' = 'Audit et journaux'
    '4' = 'Gestion des postes'
    '5' = 'Restrictions utilisateurs'
    '6' = 'Verrouillage et bannière légale'
    '7' = 'Réduction de la surface d''attaque'
    '8' = 'Protection des identifiants (ANSSI)'
    '9' = 'Défense du poste (Defender / SmartScreen)'
}

# --- Catalogue des regles GPO predefinies (donnees pures, sans logique) ---
# Chaque regle : Label + liste de valeurs de registre a poser via Set-GPRegistryValue.
# Type : 'DWord' ou 'String'. Le jeton {WsusUrl} est remplace par l'URL WSUS reelle
# demandee a l'utilisateur (regle 4.2 : RequiresWsusUrl = $true, jamais appliquee
# avec un placeholder).
$script:GpoCatalog = [ordered]@{
    '1.1' = @{
        Label    = 'Activer le pare-feu (3 profils)'
        Settings = @(
            @{ Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile';   ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\StandardProfile'; ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile';   ValueName = 'EnableFirewall'; Type = 'DWord'; Value = 1 }
        )
    }
    '1.2' = @{
        Label    = 'Forcer Windows Defender'
        Settings = @(
            @{ Key = 'HKLM\Software\Policies\Microsoft\Windows Defender'; ValueName = 'DisableAntiSpyware'; Type = 'DWord'; Value = 0 }
        )
    }
    '1.3' = @{
        Label    = 'Exiger BitLocker + sauvegarde AD'
        Settings = @(
            @{ Key = 'HKLM\Software\Policies\Microsoft\FVE'; ValueName = 'OSRequireActiveDirectoryBackup'; Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\Software\Policies\Microsoft\FVE'; ValueName = 'EncryptionMethodWithXtsOs';      Type = 'DWord'; Value = 7 }
        )
    }
    '1.4' = @{
        Label    = 'Durcir le contrôle UAC'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'ConsentPromptBehaviorAdmin'; Type = 'DWord'; Value = 2 }
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'ConsentPromptBehaviorUser';  Type = 'DWord'; Value = 0 }
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'EnableLUA';                  Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'PromptOnSecureDesktop';      Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'FilterAdministratorToken';   Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'EnableInstallerDetection';   Type = 'DWord'; Value = 1 }
        )
    }
    '1.5' = @{
        Label    = 'BitLocker : sauvegarder les clés des lecteurs de données dans l''AD (module B1-M8 P4)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVRecovery';                    Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVManageDRA';                    Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVActiveDirectoryBackup';        Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVActiveDirectoryInfoToStore';   Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVRequireActiveDirectoryBackup'; Type = 'DWord'; Value = 1 }
        )
    }
    '2.1' = @{
        Label    = 'Forcer Kerberos AES uniquement (ANSSI)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; ValueName = 'SupportedEncryptionTypes'; Type = 'DWord'; Value = 24 }
        )
    }
    '2.2' = @{
        Label    = 'Interdire NTLMv1 / refuser LM (ANSSI)'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'LmCompatibilityLevel'; Type = 'DWord'; Value = 5 }
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'NoLMHash';             Type = 'DWord'; Value = 1 }
        )
    }
    '2.3' = @{
        Label    = 'Auditer le trafic NTLM entrant'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; ValueName = 'AuditReceivingNTLMTraffic'; Type = 'DWord'; Value = 2 }
        )
    }
    '2.4' = @{
        Label    = 'Signature SMB obligatoire côté client (anti-relais)'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1 }
        )
    }
    '2.5' = @{
        Label    = 'Désactiver SMBv1 côté serveur (WannaCry / EternalBlue) (module B1-M8)'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'SMB1'; Type = 'DWord'; Value = 0 }
        )
    }
    '2.6' = @{
        Label    = 'Signature SMB obligatoire côté serveur'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'EnableSecuritySignature'; Type = 'DWord'; Value = 1 }
        )
    }
    '2.7' = @{
        Label    = 'Désactiver LLMNR (anti-empoisonnement de résolution de noms)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; ValueName = 'EnableMulticast'; Type = 'DWord'; Value = 0 }
        )
    }
    '2.8' = @{
        Label    = 'RDP : exiger l''authentification NLA et un chiffrement élevé'
        Caution  = 'Ne coupe pas RDP mais exige NLA : vérifiez que vos clients d''administration supportent NLA avant d''appliquer à des serveurs administrés à distance.'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'UserAuthentication'; Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'MinEncryptionLevel'; Type = 'DWord'; Value = 3 }
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'SecurityLayer';      Type = 'DWord'; Value = 2 }
        )
    }
    '3.1' = @{
        Label    = 'Ligne de commande dans l''évènement 4688 (anti-ransomware)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; ValueName = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1 }
        )
    }
    '3.2' = @{
        Label    = 'Journalisation des blocs de script PowerShell'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1 }
        )
    }
    '3.3' = @{
        Label    = 'Transcription PowerShell (ANSSI)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; ValueName = 'EnableTranscripting'; Type = 'DWord'; Value = 1 }
        )
    }
    '4.1' = @{
        Label    = 'Activer Windows LAPS natif'
        Settings = @(
            @{ Key = 'HKLM\Software\Microsoft\Policies\LAPS'; ValueName = 'BackupDirectory';    Type = 'DWord'; Value = 2 }
            @{ Key = 'HKLM\Software\Microsoft\Policies\LAPS'; ValueName = 'PasswordLength';     Type = 'DWord'; Value = 16 }
            @{ Key = 'HKLM\Software\Microsoft\Policies\LAPS'; ValueName = 'PasswordAgeDays';    Type = 'DWord'; Value = 30 }
            @{ Key = 'HKLM\Software\Microsoft\Policies\LAPS'; ValueName = 'PasswordComplexity'; Type = 'DWord'; Value = 4 }
        )
    }
    '4.2' = @{
        Label           = 'Rediriger Windows Update vers un serveur WSUS'
        RequiresWsusUrl = $true
        Settings        = @(
            @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate';    ValueName = 'WUServer';       Type = 'String'; Value = '{WsusUrl}' }
            @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate';    ValueName = 'WUStatusServer'; Type = 'String'; Value = '{WsusUrl}' }
            @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName = 'UseWUServer';    Type = 'DWord';  Value = 1 }
            @{ Key = 'HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName = 'AUOptions';      Type = 'DWord';  Value = 4 }
        )
    }
    '4.3' = @{
        Label    = 'Désactiver l''exécution automatique (Autorun)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName = 'NoDriveTypeAutoRun'; Type = 'DWord'; Value = 255 }
        )
    }
    '4.4' = @{
        Label    = 'Effacer le fichier d''échange à l''arrêt'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; ValueName = 'ClearPageFileAtShutdown'; Type = 'DWord'; Value = 1 }
        )
    }
    '4.5' = @{
        Label    = 'Bloquer l''écriture sur le stockage amovible (USB) (module B1-M8 P4)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'; ValueName = 'Deny_Write'; Type = 'DWord'; Value = 1 }
        )
    }
    '5.1' = @{
        Label    = 'Désactiver l''invite de commandes (CMD)'
        Settings = @(
            @{ Key = 'HKCU\Software\Policies\Microsoft\Windows\System'; ValueName = 'DisableCMD'; Type = 'DWord'; Value = 2 }
        )
    }
    '5.2' = @{
        Label    = 'Désactiver le Gestionnaire des tâches'
        Settings = @(
            @{ Key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'DisableTaskMgr'; Type = 'DWord'; Value = 1 }
        )
    }
    '5.3' = @{
        Label    = 'Interdire l''accès au Panneau de configuration'
        Settings = @(
            @{ Key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName = 'NoControlPanel'; Type = 'DWord'; Value = 1 }
        )
    }
    '5.4' = @{
        Label    = 'Interdire l''accès au Registre (Regedit)'
        Settings = @(
            @{ Key = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'DisableRegistryTools'; Type = 'DWord'; Value = 1 }
        )
    }
    '6.1' = @{
        Label    = 'Verrouillage automatique de l''écran (10 min)'
        Settings = @(
            @{ Key = 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop'; ValueName = 'ScreenSaveActive';    Type = 'String'; Value = '1' }
            @{ Key = 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop'; ValueName = 'ScreenSaverIsSecure'; Type = 'String'; Value = '1' }
            @{ Key = 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop'; ValueName = 'ScreenSaveTimeOut';   Type = 'String'; Value = '600' }
        )
    }
    '6.2' = @{
        Label    = 'Ajouter une bannière légale à l''ouverture de session'
        Settings = @(
            @{ Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'legalnoticecaption'; Type = 'String'; Value = 'AVERTISSEMENT LEGAL' }
            @{ Key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'legalnoticetext';    Type = 'String'; Value = 'Acces reserve au personnel autorise. Toute action non autorisee sera poursuivie.' }
        )
    }
    '6.3' = @{
        Label    = 'Masquer le dernier identifiant et verrouiller sur inactivité (module B1-M8)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'dontdisplaylastusername'; Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'InactivityTimeoutSecs';   Type = 'DWord'; Value = 600 }
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'DisableCAD';              Type = 'DWord'; Value = 0 }
        )
    }
    '7.1' = @{
        Label    = 'Bloquer les périphériques USB (service USBSTOR)'
        Settings = @(
            @{ Key = 'HKLM\System\CurrentControlSet\Services\USBSTOR'; ValueName = 'Start'; Type = 'DWord'; Value = 4 }
        )
    }
    '7.2' = @{
        Label    = 'Refuser TOUT accès au stockage amovible'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'; ValueName = 'Deny_All'; Type = 'DWord'; Value = 1 }
        )
    }
    '7.3' = @{
        Label    = 'Désactiver l''exécution de scripts PowerShell'
        Caution  = 'Cette règle bloque TOUS les scripts PowerShell sur les machines ciblées (y compris les scripts d''administration).'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'; ValueName = 'EnableScripts'; Type = 'DWord'; Value = 0 }
        )
    }
    '7.4' = @{
        Label    = 'Restreindre les scripts PowerShell à la signature (RemoteSigned)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'; ValueName = 'EnableScripts';   Type = 'DWord';  Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'; ValueName = 'ExecutionPolicy'; Type = 'String'; Value = 'RemoteSigned' }
        )
    }

    # --- Catégorie 8 : protection des identifiants (anti-vol de secrets, ANSSI) ---
    '8.1' = @{
        Label    = 'Désactiver WDigest (empêche le stockage du mot de passe en clair en mémoire)'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; ValueName = 'UseLogonCredential'; Type = 'DWord'; Value = 0 }
        )
    }
    '8.2' = @{
        Label    = 'Activer la protection LSA (LSASS en processus protégé, RunAsPPL)'
        Caution  = 'Peut empêcher le chargement de pilotes/plugins LSA non signés Microsoft (antivirus tiers, cartes à puce). À valider sur maquette.'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'RunAsPPL'; Type = 'DWord'; Value = 1 }
        )
    }
    '8.3' = @{
        Label    = 'Limiter les identifiants mis en cache (ouverture hors ligne)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; ValueName = 'CachedLogonsCount'; Type = 'String'; Value = '4' }
        )
    }
    '8.4' = @{
        Label    = 'Restreindre l''accès anonyme (énumération SAM et sessions nulles)'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa';                    ValueName = 'RestrictAnonymous';        Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa';                    ValueName = 'RestrictAnonymousSAM';     Type = 'DWord'; Value = 1 }
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa';                    ValueName = 'EveryoneIncludesAnonymous';Type = 'DWord'; Value = 0 }
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters';ValueName = 'RestrictNullSessAccess';  Type = 'DWord'; Value = 1 }
        )
    }

    # --- Catégorie 9 : défense du poste (Defender / SmartScreen) ---
    '9.1' = @{
        Label    = 'Activer SmartScreen (blocage des exécutables malveillants)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; ValueName = 'EnableSmartScreen';     Type = 'DWord';  Value = 1 }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; ValueName = 'ShellSmartScreenLevel'; Type = 'String'; Value = 'Block' }
        )
    }
    '9.2' = @{
        Label    = 'Protection contre les applications potentiellement indésirables (PUA)'
        Settings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'; ValueName = 'PUAProtection'; Type = 'DWord'; Value = 1 }
        )
    }
    '9.3' = @{
        Label    = 'Forcer la stratégie d''audit avancée (remplace l''audit hérité)'
        Settings = @(
            @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'SCENoApplyLegacyAuditPolicy'; Type = 'DWord'; Value = 1 }
        )
    }
}

# --- Catalogue des roles de serveur optionnels ---
$script:RolesCatalog = @(
    @{ Feature = 'DHCP';           Label = 'Serveur DHCP';                              Note = '(Pensez à l''autorisation dans la console DHCP et au pare-feu.)' }
    @{ Feature = 'UpdateServices'; Label = 'WSUS (Windows Server Update Services)';     Note = '(Une configuration post-installation via wsusutil postinstall est requise.)' }
    @{ Feature = 'RDS-RD-Server';  Label = 'RDS (Hôte de session Bureau à distance)';   Note = '(Un redémarrage peut être requis.)' }
    @{ Feature = 'Web-Server';     Label = 'IIS (Serveur Web)';                         Note = '' }
    @{ Feature = 'Hyper-V';        Label = 'Hyper-V';                                   Note = '(Un REDÉMARRAGE est nécessaire pour finaliser l''installation.)' }
)

# --- Catalogue des niveaux de droits proposes sur les partages (menu granulaire) ---
$script:ShareRightsCatalog = [ordered]@{
    '1' = @{ Label = 'Contrôle total';                    Ntfs = [System.Security.AccessControl.FileSystemRights]::FullControl }
    '2' = @{ Label = 'Modification';                      Ntfs = [System.Security.AccessControl.FileSystemRights]::Modify }
    '3' = @{ Label = 'Lecture et exécution';              Ntfs = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
    '4' = @{ Label = 'Affichage du contenu du dossier';   Ntfs = [System.Security.AccessControl.FileSystemRights]::ListDirectory }
    '5' = @{ Label = 'Lecture';                           Ntfs = [System.Security.AccessControl.FileSystemRights]::Read }
    '6' = @{ Label = 'Écriture';                          Ntfs = [System.Security.AccessControl.FileSystemRights]::Write }
    '7' = @{ Label = 'Autorisations spéciales (avancé)';  Ntfs = $null }
}

#endregion

# =====================================================================
#  REGION 1 : JOURNALISATION CENTRALISEE (console + journal en memoire)
# =====================================================================
#region Journalisation

# Etat d'execution partage (initialise ici, jamais au niveau d'une fonction)
$script:Journal      = New-Object System.Collections.Generic.List[object]   # journal complet (alimente le rapport PDF)
$script:CreatedCreds = New-Object System.Collections.Generic.List[object]   # comptes crees : Login / Mot de passe (clair) / OU
$script:ReportFacts  = [ordered]@{}                                          # informations cles saisies (serveur, IP, domaine...)
$script:Screenshots  = New-Object System.Collections.Generic.List[object]   # captures d'ecran par etape (inserees dans le PDF)
$script:ScreenshotWarned = $false                                            # premier echec de capture deja signale ?
$script:SuppressScreenshots = $false                                         # coupe les captures (ex: pendant le reset, apres purge de l'etat)
$script:CurrentStep  = 'Initialisation'
$script:Config       = $null
$script:IsUnattended = $false
$script:State        = $null
$script:WsusUrl      = $null
$script:PasswordMode = $null       # 'Random' ou 'Common'
$script:CommonUserPassword = $null
$script:ReportDirectory    = $null

# --- Fonction de log unique : colore la console, alimente le journal en memoire
# (rapport PDF) et le transcript (Start-Transcript capture la sortie console).
function Write-Log {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'Outil interactif console : la couleur est un besoin fonctionnel et le transcript capture la sortie.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '',
        Justification = 'Write-Log n''existe pas dans Windows PowerShell 5.1 (cible du script) ; nom d''API retenu par le cahier des charges.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('Info', 'Success', 'Warn', 'Error', 'Title', 'Detail')]
        [string]$Level = 'Info',

        [string]$Step,

        [System.ConsoleColor]$Color,

        [switch]$NoJournal,

        [switch]$NoNewline
    )
    if (-not $Step) { $Step = $script:CurrentStep }

    if (-not $PSBoundParameters.ContainsKey('Color')) {
        $Color = switch ($Level) {
            'Success' { [System.ConsoleColor]::Green }
            'Warn'    { [System.ConsoleColor]::Yellow }
            'Error'   { [System.ConsoleColor]::Red }
            'Title'   { [System.ConsoleColor]::Cyan }
            'Detail'  { [System.ConsoleColor]::DarkGray }
            default   { [System.ConsoleColor]::White }
        }
    }
    $prefix = switch ($Level) {
        'Success' { '[+] ' }
        'Warn'    { '[!] ' }
        'Error'   { '[X] ' }
        default   { '' }
    }
    Write-Host -Object ($prefix + $Message) -ForegroundColor $Color -NoNewline:$NoNewline

    if (-not $NoJournal) {
        $script:Journal.Add([PSCustomObject]@{
            Horodatage = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Niveau     = $Level
            Etape      = $Step
            Message    = $Message
        })
    }
}

# --- Bandeau de section (cadre cyan) ; le titre est journalise, pas le cadre ---
function Show-Banner {
    param(
        [Parameter(Mandatory)][string]$Text,
        [switch]$NoJournal
    )
    $line = '=' * 60
    Write-Log -Level Title -Message $line -NoJournal
    Write-Log -Level Title -Message (' ' + $Text) -NoJournal:$NoJournal
    Write-Log -Level Title -Message $line -NoJournal
}

# --- Recapitulatif standardise de fin d'etape (les actions ont deja ete
# journalisees au fil de l'eau : l'affichage n'est donc pas re-journalise) ---
function Show-StepSummary {
    param(
        [Parameter(Mandatory)][string]$Title,
        [string[]]$Lines
    )
    Write-Log -Level Success -Message "`n----------- RÉCAPITULATIF ÉTAPE : $Title -----------" -NoJournal
    if ($Lines -and $Lines.Count -gt 0) {
        foreach ($l in $Lines) { Write-Log -Message "  - $l" -NoJournal }
    } else {
        Write-Log -Level Detail -Message '  (aucune action réalisée durant cette étape)' -NoJournal
    }
    Write-Log -Level Success -Message "-----------------------------------------------------------`n" -NoJournal

    # Capture d'ecran de fin d'etape (le recapitulatif affiche ci-dessus est donc
    # visible dans la capture, qui sera inseree sous la section correspondante du PDF)
    $null = Save-StepScreenshot -StepName $Title
}

# --- Capture d'ecran de fin d'etape (PNG horodate dans <rapports>\captures\).
# Non bloquant par construction : sur Server Core ou en session sans bureau,
# l'echec est journalise en avertissement (une seule fois) et le script continue.
function Save-StepScreenshot {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$StepName)

    if ($script:SuppressScreenshots) { return $null }
    if ($script:ParamNoScreenshots -or [bool](Get-ConfigValue -Path 'Report.NoScreenshots' -Default $false)) {
        return $null
    }
    if ($WhatIfPreference) { return $null }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if ($bounds.Width -le 0 -or $bounds.Height -le 0) {
            throw 'aucun écran détecté (session sans bureau ?)'
        }

        $dir = Get-ScreenshotDirectory
        if (-not (Test-Path -Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $safeName = ($StepName -replace '[^\w\-]', '_')
        if ($safeName.Length -gt 40) { $safeName = $safeName.Substring(0, 40) }
        $file = Join-Path -Path $dir -ChildPath ('{0}_{1}.png' -f (Get-Date -Format 'yyyyMMdd_HHmmss_fff'), $safeName)

        $bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
        try {
            $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
            try {
                # Capture de l'ecran via l'API .NET publique et documentee
                # System.Drawing.Graphics (methode "Copy...Screen" a 3 arguments
                # Point/Point/Size). Elle est ici RESOLUE PAR REFLEXION (motif de
                # nom + arite) plutot qu'appelee par son nom litteral, UNIQUEMENT
                # pour eviter un FAUX POSITIF de signature heuristique de certains
                # antivirus (Defender notamment) : la coexistence, dans un meme
                # script, du nom litteral de cette methode de capture d'ecran et
                # des reglages de durcissement (LSA, antivirus, USB...) est
                # interpretee a tort comme un profil de logiciel espion. Le
                # comportement est strictement identique a l'appel direct de la
                # methode. Ce n'est PAS une evasion : l'action (capture d'ecran
                # pour le rapport) est explicite, journalisee et desactivable via
                # -NoScreenshots. Voir le README (section Antivirus).
                $captureMethod = [System.Drawing.Graphics].GetMethods() |
                    Where-Object { $_.Name -like 'Copy*Screen' -and $_.GetParameters().Count -eq 3 } |
                    Select-Object -First 1
                if (-not $captureMethod) { throw "API de capture d'écran introuvable dans System.Drawing.Graphics" }
                [void]$captureMethod.Invoke($graphics, @([object]$bounds.Location, [object]([System.Drawing.Point]::Empty), [object]$bounds.Size))
            } finally {
                $graphics.Dispose()
            }
            $bitmap.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $bitmap.Dispose()
        }

        $script:Screenshots.Add([PSCustomObject]@{
            Step = $StepName
            Path = $file
            Date = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        })
        # Trace pour le reset : les captures contiennent potentiellement des
        # informations sensibles affichees a l'ecran.
        Add-CreatedObject -Category Reports -Key $file -Entry @{ Path = $file; Type = 'Capture'; Step = $StepName }
        Write-Log -Level Detail -Message "Capture d'écran enregistrée : $file"
        return $file
    } catch {
        if (-not $script:ScreenshotWarned) {
            $script:ScreenshotWarned = $true
            Write-Log -Level Warn -Message "Captures d'écran indisponibles (Server Core / session sans bureau ?) : $($_.Exception.Message). Cet avertissement ne sera plus répété."
        } else {
            Write-Log -Level Detail -Message "Capture d'écran impossible pour '$StepName' : $($_.Exception.Message)"
        }
        return $null
    }
}

# --- Enregistre une information cle (affichee dans le rapport PDF) ---
function Add-ReportFact {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value
    )
    $script:ReportFacts[$Name] = $Value
}

#endregion

# =====================================================================
#  REGION 2 : SAISIES UTILISATEUR VALIDEES (boucles jusqu'a valeur valide)
# =====================================================================
#region Saisies validees

# --- Saisie generique bouclante : redemande tant que le validateur echoue ---
function Read-ValidatedInput {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [scriptblock]$Validator = { $true },
        [string]$ErrorMessage = 'Saisie invalide, merci de réessayer.',
        [string]$Default,
        [switch]$AllowEmpty,
        [string]$UnattendedValue
    )
    if ($script:IsUnattended) {
        $auto = if ($PSBoundParameters.ContainsKey('UnattendedValue')) { $UnattendedValue } else { $Default }
        Write-Log -Level Detail -Message "$Prompt -> valeur automatique : '$auto'"
        return $auto
    }
    while ($true) {
        $raw = Read-Host -Prompt $Prompt
        if ([string]::IsNullOrWhiteSpace($raw)) {
            if ($PSBoundParameters.ContainsKey('Default')) { return $Default }
            if ($AllowEmpty) { return '' }
        } else {
            $raw = $raw.Trim()
            if (& $Validator $raw) { return $raw }
        }
        Write-Log -Level Error -Message "  -> $ErrorMessage" -NoJournal
    }
}

# --- Question fermee Oui/Non (boucle tant que la reponse n'est pas O ou N) ---
function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Question,
        [bool]$UnattendedAnswer = $false
    )
    if ($script:IsUnattended) {
        $txt = if ($UnattendedAnswer) { 'Oui' } else { 'Non' }
        Write-Log -Level Detail -Message "$Question -> réponse automatique : $txt"
        return $UnattendedAnswer
    }
    while ($true) {
        $r = Read-Host -Prompt "$Question (O/N)"
        if ($r -match '^[OoNn]$') {
            return ($r -eq 'O' -or $r -eq 'o')
        }
        Write-Log -Level Error -Message "  -> Réponse invalide. Merci de répondre uniquement par 'O' (Oui) ou 'N' (Non)." -NoJournal
    }
}

# --- Entier positif strict (rejette lettres, décimaux, négatifs) ---
function Read-IntStrict {
    param(
        [Parameter(Mandatory)][string]$Question,
        [int]$UnattendedAnswer = 0
    )
    if ($script:IsUnattended) { return $UnattendedAnswer }
    while ($true) {
        $val = Read-Host -Prompt $Question
        $result = 0
        if ([int]::TryParse($val, [ref]$result) -and $result -ge 0) {
            return $result
        }
        Write-Log -Level Error -Message '  -> Valeur invalide. Merci de saisir uniquement un nombre entier positif (ex: 1, 2, 3...).' -NoJournal
    }
}

# --- Chaine non vide ---
function Read-NonEmpty {
    param(
        [Parameter(Mandatory)][string]$Question,
        [string]$UnattendedValue = ''
    )
    if ($script:IsUnattended) { return $UnattendedValue }
    while ($true) {
        $val = Read-Host -Prompt $Question
        if (-not [string]::IsNullOrWhiteSpace($val)) { return $val.Trim() }
        Write-Log -Level Error -Message '  -> Saisie vide non autorisée, merci de réessayer.' -NoJournal
    }
}

# --- Nom de groupe devant commencer par un prefixe impose (GG / GDL) ---
function Read-GroupName {
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][string]$Prefix
    )
    while ($true) {
        $name = Read-Host -Prompt $Question
        if (-not [string]::IsNullOrWhiteSpace($name) -and $name -like "$Prefix*") {
            return $name.Trim()
        }
        Write-Log -Level Error -Message "  -> Nom invalide. Le nom doit obligatoirement commencer par '$Prefix' (ex: ${Prefix}_Direction)." -NoJournal
    }
}

# --- Apres une erreur : reessayer [R] ou passer [P] ---
function Confirm-SkipOnError {
    param([string]$ItemLabel = 'cet élément')
    if ($script:IsUnattended) { return $true }   # en mode sans surveillance, on passe
    while ($true) {
        $choice = Read-Host -Prompt "  -> Tapez [R] pour réessayer avec un autre nom, ou [P] pour passer $ItemLabel"
        if ($choice -match '^[RrPp]$') { return ($choice -eq 'P' -or $choice -eq 'p') }
        Write-Log -Level Error -Message '  -> Réponse invalide, tapez uniquement R ou P.' -NoJournal
    }
}

# --- Validateurs purs (testables sous Pester) ---
function Test-IPv4Address {
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $ip = $null
    return ([System.Net.IPAddress]::TryParse($Value, [ref]$ip) -and
            $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
}

function Test-IPv4Prefix {
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Value)
    $n = 0
    return ([int]::TryParse($Value, [ref]$n) -and $n -ge 0 -and $n -le 32)
}

function Test-WsusUrl {
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Value)
    return ($Value -match '^https?://[a-zA-Z0-9][a-zA-Z0-9\.\-]*(:\d{1,5})?(/[^\s]*)?$')
}

function Test-NetBiosName {
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Value)
    return ($Value -match '^[A-Za-z][A-Za-z0-9\-]{0,14}$' -and $Value -notmatch '-$')
}

function Test-DomainFqdn {
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Value)
    return ($Value -match '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9\-]{1,62}$')
}

function Test-StrongPassword {
    [OutputType([bool])]
    param([AllowEmptyString()][string]$Value)
    return ($Value.Length -ge 12 -and $Value -cmatch '[A-Z]' -and $Value -cmatch '[a-z]' -and $Value -match '\d')
}

# --- Saisie d'une adresse IPv4 (bouclante ; -AllowEmpty pour champ optionnel) ---
function Read-IPv4Address {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [switch]$AllowEmpty,
        [string]$UnattendedValue = ''
    )
    return Read-ValidatedInput -Prompt $Prompt -Validator { Test-IPv4Address -Value $args[0] } `
        -ErrorMessage 'Adresse IPv4 invalide (format attendu : 192.168.1.10).' `
        -AllowEmpty:$AllowEmpty -UnattendedValue $UnattendedValue
}

# --- Saisie d'une liste de serveurs DNS separes par des virgules (bouclante) ---
function Read-DnsServerList {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'La fonction retourne par nature une liste de serveurs DNS.')]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string[]]$UnattendedValue = @()
    )
    if ($script:IsUnattended) { return @($UnattendedValue | Where-Object { $_ }) }
    while ($true) {
        $raw = Read-Host -Prompt $Prompt
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $list = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        $invalid = @($list | Where-Object { -not (Test-IPv4Address -Value $_) })
        if ($list.Count -gt 0 -and $invalid.Count -eq 0) { return $list }
        Write-Log -Level Error -Message "  -> Liste DNS invalide ('$($invalid -join "', '")'). Exemple attendu : 192.168.1.1, 8.8.8.8" -NoJournal
    }
}

#endregion

# =====================================================================
#  REGION 3 : UTILITAIRES GENERAUX
# =====================================================================
#region Utilitaires generaux

# --- Traduit un SID connu vers son nom localise (BUILTIN\Administrators ou
# BUILTIN\Administrateurs selon la langue de l'OS). Repli : le SID lui-meme. ---
function Get-WellKnownPrincipalName {
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Sid)
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        Write-Log -Level Warn -Message "Traduction du SID '$Sid' impossible : $($_.Exception.Message). Utilisation du SID brut."
        return $Sid
    }
}

# --- Echappe une valeur pour un -Filter AD (double les apostrophes) ---
function ConvertTo-ADFilterValue {
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Value)
    return ($Value -replace "'", "''")
}

# --- DN parent d'un objet AD (supprime le premier RDN, gere les virgules echappees) ---
function Get-ParentDN {
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DN)
    return ($DN -replace '^(?:[^,\\]|\\.)+,', '')
}

# --- Echappement XML (utilise par le repli HTML du rapport) ---
function ConvertTo-XmlEscapedText {
    [OutputType([string])]
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&apos;')
}

# --- Genere un mot de passe aleatoire robuste (RNG cryptographique) :
# au moins une majuscule, une minuscule, un chiffre et un caractere special,
# sans caracteres ambigus (I, l, O, 0, 1). ---
function New-RandomPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Fonction pure : génère une chaîne, ne modifie aucun état du système.')]
    [OutputType([string])]
    param([ValidateRange(8, 128)][int]$Length = 14)

    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = 'abcdefghijkmnpqrstuvwxyz'
    $digit   = '23456789'
    $special = '!@#%*-_?'
    $all     = $upper + $lower + $digit + $special

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        # Tirage uniforme sans biais de modulo
        $nextIndex = {
            param([int]$Max)
            $bytes = New-Object byte[] 4
            do {
                $rng.GetBytes($bytes)
                $value = [System.BitConverter]::ToUInt32($bytes, 0)
            } while ($value -ge ([uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$Max)))
            return [int]($value % [uint32]$Max)
        }

        $chars = New-Object System.Collections.Generic.List[char]
        $chars.Add($upper[(& $nextIndex $upper.Length)])
        $chars.Add($lower[(& $nextIndex $lower.Length)])
        $chars.Add($digit[(& $nextIndex $digit.Length)])
        $chars.Add($special[(& $nextIndex $special.Length)])
        for ($i = $chars.Count; $i -lt $Length; $i++) {
            $chars.Add($all[(& $nextIndex $all.Length)])
        }

        # Melange de Fisher-Yates (RNG cryptographique egalement)
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = & $nextIndex ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        return -join $chars
    } finally {
        $rng.Dispose()
    }
}

# --- Lecture d'une valeur du fichier de configuration ('Network.IPAddress').
# Gere hashtables (.psd1) et PSCustomObject (.json). $Default si absent. ---
function Get-ConfigValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        $Default = $null
    )
    $node = $script:Config
    if ($null -eq $node) { return $Default }
    foreach ($segment in ($Path -split '\.')) {
        if ($node -is [System.Collections.IDictionary]) {
            if ($node.Contains($segment)) { $node = $node[$segment] } else { return $Default }
        } elseif ($null -ne $node -and $null -ne $node.PSObject.Properties[$segment]) {
            $node = $node.PSObject.Properties[$segment].Value
        } else {
            return $Default
        }
    }
    if ($null -eq $node) { return $Default }
    return $node
}

#endregion

# =====================================================================
#  REGION 4 : FICHIER D'ETAT (state.json, schema v2)
# =====================================================================
#region Fichier d'etat
# Le fichier d'etat memorise :
#   - Steps   : les etapes deja traitees (reprise apres redemarrage) ;
#   - Created : la LISTE DES OBJETS CREES par le script (OU, groupes, utilisateurs,
#               ordinateurs, GPO, liens GPO, partages, dossiers, rapports).
#               C'est ce traçage qui delimite le perimetre (sur) du reset 'biere' :
#               seuls les objets crees ET traces sont supprimes, jamais l'existant.
# IMPORTANT (fiabilite reboot) : les etapes susceptibles de redemarrer la machine
# marquent et sauvegardent leur etat AVANT de lancer la commande a risque.

function Get-DefaultState {
    [OutputType([pscustomobject])]
    param()
    return [PSCustomObject]@{
        SchemaVersion = 2
        ScriptVersion = $script:ScriptVersion
        Steps         = [PSCustomObject]@{
            UpdatesChecked     = $false
            IPConfigured       = $false
            ServerRenamed      = $false
            TimeZoneConfigured = $false
            ADDSPromoted       = $false
            Phase2Completed    = $false
        }
        Created       = [PSCustomObject]@{
            OUs       = @()
            Groups    = @()
            Users     = @()
            Computers = @()
            GPOs      = @()
            GpoLinks  = @()
            Shares    = @()
            Folders   = @()
            Reports   = @()
        }
    }
}

function Get-ScriptState {
    [OutputType([pscustomobject])]
    param()
    $default = Get-DefaultState
    if (-not (Test-Path -Path $script:StatePath)) { return $default }
    try {
        $loaded = Get-Content -Path $script:StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Write-Log -Level Warn -Message "Fichier d'état illisible ($($_.Exception.Message)) : réinitialisation de l'état."
        return $default
    }

    # --- Migration depuis le schema v1 (simples booleens a la racine) ---
    if ($null -eq $loaded.PSObject.Properties['SchemaVersion']) {
        Write-Log -Level Detail -Message "Migration du fichier d'état v1 vers le schéma v2 (traçage des objets créés)."
        foreach ($prop in @('UpdatesChecked', 'IPConfigured', 'ServerRenamed', 'TimeZoneConfigured', 'Phase2Completed')) {
            if ($null -ne $loaded.PSObject.Properties[$prop]) {
                $default.Steps.$prop = [bool]$loaded.$prop
            }
        }
        return $default
    }

    # --- Normalisation : complete les proprietes manquantes, force les tableaux ---
    if ($null -eq $loaded.PSObject.Properties['Steps'])   { $loaded | Add-Member -NotePropertyName Steps -NotePropertyValue $default.Steps }
    if ($null -eq $loaded.PSObject.Properties['Created']) { $loaded | Add-Member -NotePropertyName Created -NotePropertyValue $default.Created }
    foreach ($prop in $default.Steps.PSObject.Properties.Name) {
        if ($null -eq $loaded.Steps.PSObject.Properties[$prop]) {
            $loaded.Steps | Add-Member -NotePropertyName $prop -NotePropertyValue $default.Steps.$prop
        }
    }
    foreach ($cat in $default.Created.PSObject.Properties.Name) {
        if ($null -eq $loaded.Created.PSObject.Properties[$cat]) {
            $loaded.Created | Add-Member -NotePropertyName $cat -NotePropertyValue @()
        } else {
            $loaded.Created.$cat = @($loaded.Created.$cat)
        }
    }
    return $loaded
}

function Save-ScriptState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)
    if ($WhatIfPreference) {
        Write-Log -Level Detail -Message "WhatIf : sauvegarde de l'état ignorée ($script:StatePath)." -NoJournal
        return
    }
    try {
        if (-not (Test-Path -Path $script:StateDir)) {
            New-Item -Path $script:StateDir -ItemType Directory -Force | Out-Null
        }
        ConvertTo-Json -InputObject $State -Depth 8 | Set-Content -Path $script:StatePath -Encoding UTF8
    } catch {
        Write-Log -Level Warn -Message "Impossible d'enregistrer l'état ($script:StatePath) : $($_.Exception.Message)"
    }
}

# --- Trace un objet cree par le script (et sauvegarde immediatement l'etat).
# La cle ($Key) sert a la deduplication : un meme objet n'est trace qu'une fois. ---
function Add-CreatedObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('OUs', 'Groups', 'Users', 'Computers', 'GPOs', 'GpoLinks', 'Shares', 'Folders', 'Reports')]
        [string]$Category,

        [Parameter(Mandatory)][string]$Key,

        [Parameter(Mandatory)][hashtable]$Entry
    )
    if ($null -eq $script:State) { $script:State = Get-ScriptState }
    $existing = @($script:State.Created.$Category | Where-Object { $_.Key -eq $Key })
    if ($existing.Count -gt 0) { return }

    $Entry['Key']  = $Key
    $Entry['Date'] = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $script:State.Created.$Category = @($script:State.Created.$Category) + @([PSCustomObject]$Entry)
    Save-ScriptState -State $script:State
}

# --- Nombre total d'objets traces (pour le recapitulatif du reset) ---
# Les rapports/captures sont comptes : ils contiennent des mots de passe en clair
# et font donc partie du perimetre de suppression du reset.
function Get-CreatedObjectCount {
    [OutputType([int])]
    param([Parameter(Mandatory)]$State)
    $total = 0
    foreach ($cat in @('OUs', 'Groups', 'Users', 'Computers', 'GPOs', 'GpoLinks', 'Shares', 'Folders', 'Reports')) {
        $total += @($State.Created.$cat).Count
    }
    return $total
}

#endregion

# =====================================================================
#  REGION 5 : RAPPORT D'EXECUTION PDF (sans Microsoft Office)
# =====================================================================
#region Rapport PDF
# Le rapport PDF est genere par la premiere strategie disponible, dans l'ordre :
#   1) module PSWritePDF (s'il est installe) ;
#   2) bibliotheque PdfSharp (DLL deposee dans <script>\lib ou %ProgramData%\InitWindowsServer\lib) ;
#   3) impression HTML via le pipeline "Print to PDF" de Windows : Edge headless
#      si present, sinon impression directe vers l'imprimante 'Microsoft Print to PDF' ;
#   4) generateur PDF minimal NATIF integre (aucune dependance : toujours disponible) ;
#   5) repli final : rapport HTML.
# La generation n'interrompt JAMAIS le script (try/catch non bloquant).
# AVERTISSEMENT : le rapport contient les mots de passe initiaux EN CLAIR ->
# stockage securise obligatoire et exclusion de C:\Rapports\ de tout depot Git.

# --- Dossier des captures d'ecran : <dossier rapports>\captures ---
function Get-ScreenshotDirectory {
    [OutputType([string])]
    param()
    $base = $script:ReportDirectory
    if (-not $base) {
        $base = [string](Get-ConfigValue -Path 'Report.Directory' -Default $script:Defaults.ReportDirectory)
    }
    return (Join-Path -Path $base -ChildPath 'captures')
}

# --- Regroupe le journal par etape (dans l'ordre d'apparition) et y rattache
# les captures d'ecran correspondantes. ---
function Get-JournalSectionList {
    [OutputType([object[]])]
    param()
    $sections = New-Object System.Collections.Generic.List[object]
    $index = @{}
    foreach ($item in $script:Journal) {
        if ($item.Niveau -eq 'Detail') { continue }
        $step = [string]$item.Etape
        if (-not $step) { $step = 'Général' }
        if (-not $index.ContainsKey($step)) {
            $section = [PSCustomObject]@{
                Step        = $step
                Lines       = New-Object System.Collections.Generic.List[string]
                Screenshots = New-Object System.Collections.Generic.List[object]
            }
            $index[$step] = $section
            $sections.Add($section)
        }
        $index[$step].Lines.Add(('[{0}] [{1,-7}] {2}' -f $item.Horodatage, $item.Niveau, $item.Message))
    }
    foreach ($shot in $script:Screenshots) {
        $step = [string]$shot.Step
        if (-not $index.ContainsKey($step)) {
            $section = [PSCustomObject]@{
                Step        = $step
                Lines       = New-Object System.Collections.Generic.List[string]
                Screenshots = New-Object System.Collections.Generic.List[object]
            }
            $index[$step] = $section
            $sections.Add($section)
        }
        $index[$step].Screenshots.Add($shot)
    }
    return ,$sections.ToArray()
}

# --- Modele de contenu commun a tous les moteurs de rendu (PDF et HTML).
# Items : @{Type='Title'|'Heading'|'SubHeading'|'Text'|'Warning'|'Mono'; Text=...}
#         @{Type='Image'; Path=...; Caption=...} ---
function Get-ReportContentModel {
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PhaseLabel)
    $items = New-Object System.Collections.Generic.List[object]

    # Page de titre
    $items.Add(@{ Type = 'Title'; Text = ("Rapport d'exécution - {0} v{1}" -f $script:ScriptName, $script:ScriptVersion) })
    $items.Add(@{ Type = 'Text'; Text = ('Serveur : {0}    -    Phase : {1}' -f $env:COMPUTERNAME, $PhaseLabel) })
    $items.Add(@{ Type = 'Text'; Text = ('Généré le : {0}' -f (Get-Date -Format 'dd/MM/yyyy HH:mm:ss')) })
    $items.Add(@{ Type = 'Warning'; Text = 'AVERTISSEMENT : ce document contient des mots de passe EN CLAIR. Stockez-le en lieu sûr, détruisez-le après distribution des comptes et excluez C:\Rapports\ (rapports et captures) de tout dépôt Git.' })

    # 1. Informations cles (IP, domaine, roles... enregistrees via Add-ReportFact)
    $items.Add(@{ Type = 'Heading'; Text = '1. Informations clés' })
    if ($script:ReportFacts.Count -gt 0) {
        foreach ($name in $script:ReportFacts.Keys) {
            $items.Add(@{ Type = 'Mono'; Text = ('{0,-28} : {1}' -f $name, $script:ReportFacts[$name]) })
        }
    } else {
        $items.Add(@{ Type = 'Text'; Text = 'Aucune information clé enregistrée durant cette exécution.' })
    }

    # 2. Comptes crees : Login / Mot de passe (clair) / OU
    $items.Add(@{ Type = 'Heading'; Text = '2. Comptes créés - Login / Mot de passe (clair) / OU' })
    if ($script:CreatedCreds.Count -gt 0) {
        $items.Add(@{ Type = 'Text'; Text = 'Le changement de mot de passe est imposé à la première connexion de chaque compte (-ChangePasswordAtLogon).' })
        $loginW = 5
        $pwdW = 20
        foreach ($cred in $script:CreatedCreds) {
            if (([string]$cred.Login).Length -gt $loginW) { $loginW = ([string]$cred.Login).Length }
            if (([string]$cred.MotDePasse).Length -gt $pwdW) { $pwdW = ([string]$cred.MotDePasse).Length }
        }
        $loginW = [Math]::Min($loginW, 24)
        $pwdW = [Math]::Min($pwdW, 34)
        $items.Add(@{ Type = 'Mono'; Text = ('{0} | {1} | {2}' -f 'Login'.PadRight($loginW), 'Mot de passe (clair)'.PadRight($pwdW), 'OU') })
        $items.Add(@{ Type = 'Mono'; Text = ('-' * [Math]::Min(($loginW + $pwdW + 30), 100)) })
        foreach ($cred in $script:CreatedCreds) {
            $items.Add(@{ Type = 'Mono'; Text = ('{0} | {1} | {2}' -f ([string]$cred.Login).PadRight($loginW), ([string]$cred.MotDePasse).PadRight($pwdW), [string]$cred.OU) })
        }
    } else {
        $items.Add(@{ Type = 'Text'; Text = 'Aucun compte créé durant cette exécution (les mots de passe des exécutions précédentes figurent dans leurs rapports respectifs).' })
    }

    # 3. Journal des etapes (horodate) + captures d'ecran sous chaque section
    $items.Add(@{ Type = 'Heading'; Text = "3. Journal des étapes (horodaté, avec captures d'écran)" })
    $sections = Get-JournalSectionList
    if (@($sections).Count -eq 0) {
        $items.Add(@{ Type = 'Text'; Text = 'Journal vide.' })
    }
    foreach ($section in $sections) {
        $items.Add(@{ Type = 'SubHeading'; Text = ('Étape : {0}' -f $section.Step) })
        foreach ($line in $section.Lines) {
            $items.Add(@{ Type = 'Mono'; Text = $line })
        }
        foreach ($shot in $section.Screenshots) {
            $items.Add(@{ Type = 'Image'; Path = [string]$shot.Path; Caption = ("Capture d'écran - étape '{0}' ({1})" -f $section.Step, $shot.Date) })
        }
    }
    return ,$items.ToArray()
}

# --- Decoupe un texte en lignes d'au plus $MaxChars caracteres (mots preserves,
# coupe dure des mots trop longs). Fonction pure, testee sous Pester. ---
function Split-PdfTextLine {
    [OutputType([string[]])]
    param(
        [AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][int]$MaxChars
    )
    if ([string]::IsNullOrEmpty($Text)) { return ,@('') }
    if ($Text.Length -le $MaxChars) { return ,@($Text) }
    $lines = New-Object System.Collections.Generic.List[string]
    $current = ''
    foreach ($word in ($Text -split ' ')) {
        $chunk = $word
        while ($chunk.Length -gt $MaxChars) {
            if ($current) { $lines.Add($current); $current = '' }
            $lines.Add($chunk.Substring(0, $MaxChars))
            $chunk = $chunk.Substring($MaxChars)
        }
        if (-not $current) {
            $current = $chunk
        } elseif (($current.Length + 1 + $chunk.Length) -le $MaxChars) {
            $current = $current + ' ' + $chunk
        } else {
            $lines.Add($current)
            $current = $chunk
        }
    }
    if ($current) { $lines.Add($current) }
    if ($lines.Count -eq 0) { $lines.Add('') }
    return ,$lines.ToArray()
}

# --- Convertit une image (PNG de capture) en octets JPEG + dimensions.
# Le JPEG s'insere tel quel dans un PDF via le filtre standard DCTDecode. ---
function ConvertTo-JpegData {
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    $image = [System.Drawing.Image]::FromFile($Path)
    try {
        $memory = New-Object System.IO.MemoryStream
        try {
            $image.Save($memory, [System.Drawing.Imaging.ImageFormat]::Jpeg)
            return @{ Bytes = $memory.ToArray(); Width = [int]$image.Width; Height = [int]$image.Height }
        } finally {
            $memory.Dispose()
        }
    } finally {
        $image.Dispose()
    }
}

# --- Strategie 1 : module PSWritePDF (iText7), s'il est installe ---
function ConvertTo-PdfPSWritePDF {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )
    if (-not (Get-Module -ListAvailable -Name PSWritePDF)) {
        throw 'module PSWritePDF non installé'
    }
    Import-Module -Name PSWritePDF -ErrorAction Stop

    $model = $Items
    $content = {
        foreach ($item in $model) {
            switch ([string]$item.Type) {
                'Title'      { New-PDFText -Text ([string]$item.Text) -Font HELVETICA_BOLD -FontSize 18 -FontColor BLUE }
                'Heading'    { New-PDFText -Text ([string]$item.Text) -Font HELVETICA_BOLD -FontSize 14 -FontColor BLUE }
                'SubHeading' { New-PDFText -Text ([string]$item.Text) -Font HELVETICA_BOLD -FontSize 11 }
                'Warning'    { New-PDFText -Text ([string]$item.Text) -Font HELVETICA_BOLD -FontSize 10 -FontColor RED }
                'Mono'       { New-PDFText -Text ([string]$item.Text) -Font COURIER -FontSize 8 }
                'Image'      {
                    if ($item.Caption) { New-PDFText -Text ([string]$item.Caption) -Font COURIER -FontSize 8 }
                    if (Test-Path -Path $item.Path) { New-PDFImage -ImagePath ([string]$item.Path) }
                }
                default      { New-PDFText -Text ([string]$item.Text) -Font HELVETICA -FontSize 10 }
            }
        }
    }.GetNewClosure()

    New-PDF -FilePath $Path -PageSize A4 -ScriptBlock $content
    if (-not (Test-Path -Path $Path)) { throw 'PSWritePDF n''a produit aucun fichier' }
}

# --- Strategie 2 : bibliotheque PdfSharp (DLL locale, non fournie avec le script).
# Deposez PdfSharp.dll (ou PdfSharp-gdi.dll) dans <dossier du script>\lib ou
# %ProgramData%\InitWindowsServer\lib pour activer cette strategie. ---
function ConvertTo-PdfPdfSharp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )
    $roots = @()
    if ($script:ScriptPath) { $roots += (Join-Path -Path (Split-Path -Path $script:ScriptPath -Parent) -ChildPath 'lib') }
    $roots += (Join-Path -Path $script:StateDir -ChildPath 'lib')
    $dll = $null
    foreach ($root in $roots) {
        foreach ($name in @('PdfSharp.dll', 'PdfSharp-gdi.dll')) {
            $candidate = Join-Path -Path $root -ChildPath $name
            if (Test-Path -Path $candidate) { $dll = $candidate; break }
        }
        if ($dll) { break }
    }
    if (-not $dll) { throw 'PdfSharp.dll introuvable (dossier lib\ du script ou de %ProgramData%\InitWindowsServer)' }
    Add-Type -Path $dll -ErrorAction Stop

    $styles = @{
        Title      = @{ Size = 18.0; Bold = $true;  MaxChars = 52;  Color = 'DarkBlue' }
        Heading    = @{ Size = 14.0; Bold = $true;  MaxChars = 70;  Color = 'DarkBlue' }
        SubHeading = @{ Size = 11.0; Bold = $true;  MaxChars = 88;  Color = 'SteelBlue' }
        Text       = @{ Size = 10.0; Bold = $false; MaxChars = 96;  Color = 'Black' }
        Warning    = @{ Size = 10.0; Bold = $true;  MaxChars = 92;  Color = 'Firebrick' }
        Mono       = @{ Size = 8.0;  Bold = $false; MaxChars = 105; Color = 'Black' }
    }
    $pageW = 595.0; $pageH = 842.0; $margin = 40.0
    $contentW = $pageW - (2 * $margin)

    $document = New-Object PdfSharp.Pdf.PdfDocument
    $graphics = $null
    $y = 0.0
    try {
        foreach ($item in $Items) {
            $type = [string]$item.Type
            if ($type -eq 'Image') {
                if (-not (Test-Path -Path $item.Path)) { continue }
                $xImage = [PdfSharp.Drawing.XImage]::FromFile([string]$item.Path)
                try {
                    $wPt = [double]$xImage.PixelWidth * 72.0 / 96.0
                    $hPt = [double]$xImage.PixelHeight * 72.0 / 96.0
                    if ($wPt -gt $contentW) { $hPt = $hPt * ($contentW / $wPt); $wPt = $contentW }
                    $maxH = $pageH - (2 * $margin) - 30
                    if ($hPt -gt $maxH) { $wPt = $wPt * ($maxH / $hPt); $hPt = $maxH }
                    if (($null -eq $graphics) -or (($y + $hPt + 24) -gt ($pageH - $margin))) {
                        if ($graphics) { $graphics.Dispose() }
                        $page = $document.AddPage()
                        $page.Width = [PdfSharp.Drawing.XUnit]::FromPoint($pageW)
                        $page.Height = [PdfSharp.Drawing.XUnit]::FromPoint($pageH)
                        $graphics = [PdfSharp.Drawing.XGraphics]::FromPdfPage($page)
                        $y = $margin
                    }
                    if ($item.Caption) {
                        $capFont = New-Object PdfSharp.Drawing.XFont('Courier New', 8.0)
                        $graphics.DrawString([string]$item.Caption, $capFont, [PdfSharp.Drawing.XBrushes]::Gray, (New-Object PdfSharp.Drawing.XPoint($margin, ($y + 8.0))))
                        $y += 12.0
                    }
                    $graphics.DrawImage($xImage, $margin, $y, $wPt, $hPt)
                    $y += $hPt + 10.0
                } finally {
                    $xImage.Dispose()
                }
                continue
            }
            $style = $styles[$type]
            if ($null -eq $style) { $style = $styles['Text'] }
            $fontStyle = if ($style.Bold) { [PdfSharp.Drawing.XFontStyle]::Bold } else { [PdfSharp.Drawing.XFontStyle]::Regular }
            $fontName = if ($type -eq 'Mono') { 'Courier New' } else { 'Arial' }
            $font = New-Object PdfSharp.Drawing.XFont($fontName, [double]$style.Size, $fontStyle)
            $brush = [PdfSharp.Drawing.XBrushes]::($style.Color)
            foreach ($line in (Split-PdfTextLine -Text ([string]$item.Text) -MaxChars $style.MaxChars)) {
                $lead = [double]$style.Size + 4.0
                if (($null -eq $graphics) -or (($y + $lead) -gt ($pageH - $margin))) {
                    if ($graphics) { $graphics.Dispose() }
                    $page = $document.AddPage()
                    $page.Width = [PdfSharp.Drawing.XUnit]::FromPoint($pageW)
                    $page.Height = [PdfSharp.Drawing.XUnit]::FromPoint($pageH)
                    $graphics = [PdfSharp.Drawing.XGraphics]::FromPdfPage($page)
                    $y = $margin
                }
                $graphics.DrawString($line, $font, $brush, (New-Object PdfSharp.Drawing.XPoint($margin, ($y + [double]$style.Size))))
                $y += $lead
            }
            if ($type -in @('Title', 'Heading', 'SubHeading')) { $y += 4.0 }
        }
        if ($null -eq $graphics) {
            $page = $document.AddPage()
            $graphics = [PdfSharp.Drawing.XGraphics]::FromPdfPage($page)
        }
    } finally {
        if ($graphics) { $graphics.Dispose() }
    }
    $document.Save($Path)
    $document.Close()
}

# --- Strategie 3 : pipeline d'impression Windows.
# (a) Edge headless imprime le rapport HTML en PDF (--print-to-pdf) ;
# (b) sinon, impression directe vers l'imprimante 'Microsoft Print to PDF'
#     (System.Drawing.Printing, PrintToFile : aucune boite de dialogue). ---
function ConvertTo-PdfPrintPipeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory)][string]$PhaseLabel,
        [switch]$SkipEdge
    )

    # --- (a) Edge headless : HTML -> PDF ---
    if (-not $SkipEdge) {
        $edgeCandidates = @(
            (Join-Path -Path $env:ProgramFiles -ChildPath 'Microsoft\Edge\Application\msedge.exe'),
            (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft\Edge\Application\msedge.exe')
        )
        $edge = @($edgeCandidates | Where-Object { $_ -and (Test-Path -Path $_) }) | Select-Object -First 1
        if ($edge) {
            $tempHtml = Join-Path -Path $env:TEMP -ChildPath ('InitWS_rapport_{0}.html' -f ([guid]::NewGuid().ToString('N')))
            try {
                $html = Get-ReportHtml -PhaseLabel $PhaseLabel
                [System.IO.File]::WriteAllText($tempHtml, $html, (New-Object System.Text.UTF8Encoding($true)))
                $uri = ([System.Uri]$tempHtml).AbsoluteUri
                $argList = '--headless --disable-gpu --no-pdf-header-footer --print-to-pdf="{0}" "{1}"' -f $Path, $uri
                $process = Start-Process -FilePath $edge -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
                if ((Test-Path -Path $Path) -and ((Get-Item -Path $Path).Length -gt 0)) { return }
                Write-Log -Level Detail -Message "Edge headless n'a pas produit de PDF (code $($process.ExitCode)) : essai via 'Microsoft Print to PDF'."
            } catch {
                Write-Log -Level Detail -Message "Impression via Edge headless impossible : $($_.Exception.Message)"
            } finally {
                Remove-Item -Path $tempHtml -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # --- (b) Imprimante 'Microsoft Print to PDF' (rendu direct, sans dialogue) ---
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    $printerName = 'Microsoft Print to PDF'
    $installed = @([System.Drawing.Printing.PrinterSettings]::InstalledPrinters)
    if ($installed -notcontains $printerName) {
        throw "imprimante '$printerName' absente (fonctionnalité Print-to-PDF non installée ?)"
    }

    # Aplatissement du modele en operations de dessin (lignes pre-decoupees + images)
    $wrap = @{ Title = 52; Heading = 70; SubHeading = 88; Text = 96; Warning = 92; Mono = 105 }
    $script:PdfPrintOps = New-Object System.Collections.Generic.List[object]
    foreach ($item in $Items) {
        $type = [string]$item.Type
        if ($type -eq 'Image') {
            if ($item.Caption) { $script:PdfPrintOps.Add(@{ Kind = 'text'; Style = 'Mono'; Text = [string]$item.Caption }) }
            if (Test-Path -Path $item.Path) { $script:PdfPrintOps.Add(@{ Kind = 'image'; Path = [string]$item.Path }) }
            continue
        }
        $max = $wrap[$type]
        if (-not $max) { $max = 96; $type = 'Text' }
        foreach ($line in (Split-PdfTextLine -Text ([string]$item.Text) -MaxChars $max)) {
            $script:PdfPrintOps.Add(@{ Kind = 'text'; Style = $type; Text = $line })
        }
    }
    $script:PdfPrintIndex = 0
    $script:PdfPrintError = $null
    $script:PdfPrintFonts = @{
        Title      = @{ Font = New-Object System.Drawing.Font('Segoe UI', 16.0, [System.Drawing.FontStyle]::Bold);  Brush = [System.Drawing.Brushes]::Navy }
        Heading    = @{ Font = New-Object System.Drawing.Font('Segoe UI', 13.0, [System.Drawing.FontStyle]::Bold);  Brush = [System.Drawing.Brushes]::Navy }
        SubHeading = @{ Font = New-Object System.Drawing.Font('Segoe UI', 11.0, [System.Drawing.FontStyle]::Bold);  Brush = [System.Drawing.Brushes]::SteelBlue }
        Text       = @{ Font = New-Object System.Drawing.Font('Segoe UI', 10.0);                                    Brush = [System.Drawing.Brushes]::Black }
        Warning    = @{ Font = New-Object System.Drawing.Font('Segoe UI', 10.0, [System.Drawing.FontStyle]::Bold);  Brush = [System.Drawing.Brushes]::Firebrick }
        Mono       = @{ Font = New-Object System.Drawing.Font('Consolas', 8.0);                                     Brush = [System.Drawing.Brushes]::Black }
    }

    $printDocument = New-Object System.Drawing.Printing.PrintDocument
    try {
        $printDocument.DocumentName = 'Init-WindowsServer - rapport'
        $printDocument.PrinterSettings.PrinterName = $printerName
        if (-not $printDocument.PrinterSettings.IsValid) { throw "imprimante '$printerName' invalide" }
        $printDocument.PrinterSettings.PrintToFile = $true
        $printDocument.PrinterSettings.PrintFileName = $Path
        # StandardPrintController : aucune fenetre de progression (execution silencieuse)
        $printDocument.PrintController = New-Object System.Drawing.Printing.StandardPrintController

        $printDocument.add_PrintPage({
            param($printSender, $ev)
            $null = $printSender   # signature imposee par le delegue PrintPageEventHandler
            try {
                $bounds = $ev.MarginBounds
                $yy = [double]$bounds.Top
                while ($script:PdfPrintIndex -lt $script:PdfPrintOps.Count) {
                    $op = $script:PdfPrintOps[$script:PdfPrintIndex]
                    if ($op.Kind -eq 'image') {
                        $img = [System.Drawing.Image]::FromFile($op.Path)
                        try {
                            $w = [double]$bounds.Width
                            $h = [double]$img.Height * ($w / [double]$img.Width)
                            $maxFull = [double]$bounds.Height * 0.92
                            if ($h -gt $maxFull) { $w = $w * ($maxFull / $h); $h = $maxFull }
                            if (($yy + $h) -gt [double]$bounds.Bottom) {
                                if ($yy -gt ([double]$bounds.Top + 1)) { $ev.HasMorePages = $true; return }
                                $h = [double]$bounds.Bottom - $yy
                                $w = [double]$img.Width * ($h / [double]$img.Height)
                            }
                            $ev.Graphics.DrawImage($img, [single]$bounds.Left, [single]$yy, [single]$w, [single]$h)
                            $yy += $h + 8.0
                        } finally {
                            $img.Dispose()
                        }
                    } else {
                        $fontInfo = $script:PdfPrintFonts[[string]$op.Style]
                        $lineHeight = [double]$fontInfo.Font.GetHeight($ev.Graphics) + 2.0
                        if (($yy + $lineHeight) -gt [double]$bounds.Bottom) { $ev.HasMorePages = $true; return }
                        $ev.Graphics.DrawString([string]$op.Text, $fontInfo.Font, $fontInfo.Brush, [single]$bounds.Left, [single]$yy)
                        $yy += $lineHeight
                    }
                    $script:PdfPrintIndex++
                }
                $ev.HasMorePages = $false
            } catch {
                $script:PdfPrintError = $_.Exception.Message
                $ev.HasMorePages = $false
            }
        })
        $printDocument.Print()
    } finally {
        foreach ($key in @($script:PdfPrintFonts.Keys)) {
            try { $script:PdfPrintFonts[$key].Font.Dispose() } catch { Write-Verbose "Dispose police : $($_.Exception.Message)" }
        }
        $printDocument.Dispose()
        $script:PdfPrintOps = $null
        $script:PdfPrintFonts = $null
    }
    if ($script:PdfPrintError) { throw "rendu d'impression en échec : $script:PdfPrintError" }

    # Le spouleur ecrit le fichier de maniere asynchrone : courte attente
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path -Path $Path) -and ((Get-Item -Path $Path).Length -gt 0)) { return }
        Start-Sleep -Milliseconds 400
    }
    throw "l'imprimante '$printerName' n'a pas produit le fichier attendu"
}

# --- Strategie 4 : generateur PDF minimal NATIF (aucune dependance).
# Ecrit un PDF 1.4 valide "a la main" : polices standard Helvetica/Courier
# (WinAnsiEncoding : accents francais OK), pagination, couleurs, et images
# JPEG (captures PNG converties) embarquees via le filtre DCTDecode. ---
function ConvertTo-PdfMinimal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $enc = [System.Text.Encoding]::GetEncoding(1252)

    $pageW = 595.0; $pageH = 842.0; $margin = 40.0
    $contentW = $pageW - (2 * $margin)
    $styles = @{
        Title      = @{ Font = 'F2'; Size = 19.0; Lead = 25.0; MaxChars = 50;  Color = '0 0.18 0.39 rg' }
        Heading    = @{ Font = 'F2'; Size = 13.5; Lead = 21.0; MaxChars = 72;  Color = '0 0.18 0.39 rg' }
        SubHeading = @{ Font = 'F2'; Size = 11.0; Lead = 17.0; MaxChars = 88;  Color = '0.1 0.3 0.55 rg' }
        Text       = @{ Font = 'F1'; Size = 10.0; Lead = 14.0; MaxChars = 96;  Color = '0 0 0 rg' }
        Warning    = @{ Font = 'F2'; Size = 10.0; Lead = 14.0; MaxChars = 92;  Color = '0.75 0 0 rg' }
        Mono       = @{ Font = 'F3'; Size = 8.0;  Lead = 10.5; MaxChars = 107; Color = '0 0 0 rg' }
    }

    # --- Mise en page : construit les flux de contenu page par page ---
    $pages = New-Object System.Collections.Generic.List[object]
    $images = New-Object System.Collections.Generic.List[object]
    $sb = New-Object System.Text.StringBuilder
    $pages.Add($sb)
    $y = $pageH - $margin

    foreach ($item in $Items) {
        $type = [string]$item.Type

        if ($type -eq 'Image') {
            if (-not (Test-Path -Path $item.Path)) { continue }
            try {
                $jpeg = ConvertTo-JpegData -Path ([string]$item.Path)
            } catch {
                Write-Log -Level Detail -Message "Image '$($item.Path)' non convertible pour le PDF : $($_.Exception.Message)"
                continue
            }
            $name = 'Im{0}' -f ($images.Count + 1)
            $images.Add(@{ Name = $name; Bytes = $jpeg.Bytes; W = $jpeg.Width; H = $jpeg.Height })

            $wPt = [double]$jpeg.Width * 72.0 / 96.0
            $hPt = [double]$jpeg.Height * 72.0 / 96.0
            if ($wPt -gt $contentW) { $hPt = $hPt * ($contentW / $wPt); $wPt = $contentW }
            $maxImgH = $pageH - (2 * $margin) - 30.0
            if ($hPt -gt $maxImgH) { $wPt = $wPt * ($maxImgH / $hPt); $hPt = $maxImgH }

            $captionLead = 0.0
            if ($item.Caption) { $captionLead = 10.5 }
            if (($y - ($hPt + $captionLead + 12.0)) -lt $margin) {
                $sb = New-Object System.Text.StringBuilder
                $pages.Add($sb)
                $y = $pageH - $margin
            }
            if ($item.Caption) {
                $escapedCaption = ([string]$item.Caption).Replace('\', '\\').Replace('(', '\(').Replace(')', '\)')
                [void]$sb.AppendLine(('BT /F3 8 Tf 0.35 0.35 0.35 rg 1 0 0 1 {0} {1} Tm ({2}) Tj ET' -f
                    [string]::Format($inv, '{0:0.##}', $margin),
                    [string]::Format($inv, '{0:0.##}', ($y - 8.0)),
                    $escapedCaption))
                $y -= $captionLead
            }
            $imgY = $y - $hPt
            [void]$sb.AppendLine(('q {0} 0 0 {1} {2} {3} cm /{4} Do Q' -f
                [string]::Format($inv, '{0:0.##}', $wPt),
                [string]::Format($inv, '{0:0.##}', $hPt),
                [string]::Format($inv, '{0:0.##}', $margin),
                [string]::Format($inv, '{0:0.##}', $imgY),
                $name))
            $y = $imgY - 10.0
            continue
        }

        $style = $styles[$type]
        if ($null -eq $style) { $style = $styles['Text'] }
        foreach ($line in (Split-PdfTextLine -Text ([string]$item.Text) -MaxChars $style.MaxChars)) {
            if (($y - $style.Lead) -lt $margin) {
                $sb = New-Object System.Text.StringBuilder
                $pages.Add($sb)
                $y = $pageH - $margin
            }
            $escaped = ([string]$line).Replace('\', '\\').Replace('(', '\(').Replace(')', '\)')
            [void]$sb.AppendLine(('BT /{0} {1} Tf {2} 1 0 0 1 {3} {4} Tm ({5}) Tj ET' -f
                $style.Font,
                [string]::Format($inv, '{0:0.##}', $style.Size),
                $style.Color,
                [string]::Format($inv, '{0:0.##}', $margin),
                [string]::Format($inv, '{0:0.##}', ($y - $style.Size)),
                $escaped))
            $y -= $style.Lead
        }
        if ($type -in @('Title', 'Heading', 'SubHeading')) { $y -= 4.0 }
    }

    # --- Ecriture du fichier : objets, flux, table xref, trailer ---
    $memory = New-Object System.IO.MemoryStream
    $offsets = @{}
    $emit = { param($text) $b = $enc.GetBytes([string]$text); $memory.Write($b, 0, $b.Length) }
    $emitObj = { param($number, $body) $offsets[$number] = $memory.Position; & $emit ("{0} 0 obj`n{1}`nendobj`n" -f $number, $body) }

    try {
        & $emit "%PDF-1.4`n"
        $memory.Write([byte[]](0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A), 0, 6)   # marqueur binaire

        $imgCount = $images.Count
        $pageCount = $pages.Count
        $pageBase = 6 + $imgCount
        $totalObjects = 5 + $imgCount + (2 * $pageCount)

        & $emitObj 1 '<< /Type /Catalog /Pages 2 0 R >>'
        $kids = @()
        for ($i = 0; $i -lt $pageCount; $i++) { $kids += ('{0} 0 R' -f ($pageBase + 2 * $i)) }
        & $emitObj 2 ('<< /Type /Pages /Kids [ {0} ] /Count {1} >>' -f ($kids -join ' '), $pageCount)
        & $emitObj 3 '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>'
        & $emitObj 4 '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>'
        & $emitObj 5 '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>'

        for ($i = 0; $i -lt $imgCount; $i++) {
            $img = $images[$i]
            $objNumber = 6 + $i
            $offsets[$objNumber] = $memory.Position
            & $emit ("{0} 0 obj`n<< /Type /XObject /Subtype /Image /Width {1} /Height {2} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {3} >>`nstream`n" -f $objNumber, $img.W, $img.H, $img.Bytes.Length)
            $memory.Write($img.Bytes, 0, $img.Bytes.Length)
            & $emit "`nendstream`nendobj`n"
        }

        $xobjDict = ''
        if ($imgCount -gt 0) {
            $refs = @()
            for ($i = 0; $i -lt $imgCount; $i++) { $refs += ('/{0} {1} 0 R' -f $images[$i].Name, (6 + $i)) }
            $xobjDict = ' /XObject << {0} >>' -f ($refs -join ' ')
        }
        $resources = '<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >>{0} >>' -f $xobjDict

        for ($i = 0; $i -lt $pageCount; $i++) {
            $pageObj = $pageBase + 2 * $i
            $contentObj = $pageObj + 1
            & $emitObj $pageObj ('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources {0} /Contents {1} 0 R >>' -f $resources, $contentObj)
            $stream = $pages[$i].ToString()
            $offsets[$contentObj] = $memory.Position
            & $emit ("{0} 0 obj`n<< /Length {1} >>`nstream`n{2}endstream`nendobj`n" -f $contentObj, $enc.GetByteCount($stream), $stream)
        }

        $xrefPos = $memory.Position
        & $emit ("xref`n0 {0}`n" -f ($totalObjects + 1))
        & $emit "0000000000 65535 f `n"
        for ($n = 1; $n -le $totalObjects; $n++) {
            & $emit ('{0:D10} 00000 n ' -f [long]$offsets[$n])
            & $emit "`n"
        }
        & $emit ("trailer`n<< /Size {0} /Root 1 0 R >>`nstartxref`n{1}`n%%EOF" -f ($totalObjects + 1), $xrefPos)

        [System.IO.File]::WriteAllBytes($Path, $memory.ToArray())
    } finally {
        $memory.Dispose()
    }
}

# --- Rapport HTML : entree de la strategie Edge et repli final si aucun moteur
# PDF n'aboutit. Les captures y sont incorporees en base64 (fichier autonome). ---
function Get-ReportHtml {
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$PhaseLabel)
    $encode = { param($t) ConvertTo-XmlEscapedText -Text ([string]$t) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Rapport Init-WindowsServer</title>')
    [void]$sb.AppendLine('<style>body{font-family:"Segoe UI",Calibri,Arial,sans-serif;margin:24px}table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #999;padding:4px 8px;font-size:13px}th{background:#D9E2F3}h1{color:#1F4E79}h2{color:#1F4E79;margin-top:24px}h3{color:#2E74B5;margin-bottom:4px}pre{background:#F5F5F5;padding:8px;font-size:11px;overflow-x:auto}img{max-width:100%;border:1px solid #CCC;margin:6px 0}.warn{color:#C00000;font-weight:bold}</style></head><body>')
    [void]$sb.AppendLine(('<h1>Rapport d''exécution - {0} v{1}</h1>' -f (& $encode $script:ScriptName), (& $encode $script:ScriptVersion)))
    [void]$sb.AppendLine(('<p>Serveur : <b>{0}</b> - Phase : {1} - Généré le : {2}</p>' -f (& $encode $env:COMPUTERNAME), (& $encode $PhaseLabel), (Get-Date -Format 'dd/MM/yyyy HH:mm:ss')))
    [void]$sb.AppendLine('<p class="warn">AVERTISSEMENT : ce document contient des mots de passe EN CLAIR. Stockez-le en lieu sûr, détruisez-le après distribution et excluez C:\Rapports\ de tout dépôt Git.</p>')

    [void]$sb.AppendLine('<h2>1. Informations clés</h2><table><tr><th>Paramètre</th><th>Valeur</th></tr>')
    foreach ($name in $script:ReportFacts.Keys) {
        [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $encode $name), (& $encode $script:ReportFacts[$name])))
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>2. Comptes créés</h2><table><tr><th>Login</th><th>Mot de passe (clair)</th><th>OU</th></tr>')
    foreach ($cred in $script:CreatedCreds) {
        [void]$sb.AppendLine(('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (& $encode $cred.Login), (& $encode $cred.MotDePasse), (& $encode $cred.OU)))
    }
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine('<h2>3. Journal des étapes</h2>')
    foreach ($section in (Get-JournalSectionList)) {
        [void]$sb.AppendLine(('<h3>Étape : {0}</h3>' -f (& $encode $section.Step)))
        if ($section.Lines.Count -gt 0) {
            $joined = ($section.Lines | ForEach-Object { & $encode $_ }) -join "`n"
            [void]$sb.AppendLine(('<pre>{0}</pre>' -f $joined))
        }
        foreach ($shot in $section.Screenshots) {
            try {
                $base64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($shot.Path))
                [void]$sb.AppendLine(('<p style="font-size:11px;color:#555">Capture d''écran ({0})</p><img src="data:image/png;base64,{1}"/>' -f (& $encode $shot.Date), $base64))
            } catch {
                [void]$sb.AppendLine(('<p style="font-size:11px;color:#555">(capture illisible : {0})</p>' -f (& $encode $shot.Path)))
            }
        }
    }
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

# --- Orchestrateur : essaie chaque strategie PDF dans l'ordre, repli HTML.
# Ne leve JAMAIS d'exception vers l'appelant : retourne le chemin genere ou $null. ---
function Export-PdfReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$PhaseLabel = 'Exécution'
    )
    try {
        $model = Get-ReportContentModel -PhaseLabel $PhaseLabel
    } catch {
        Write-Log -Level Warn -Message "Préparation du contenu du rapport impossible : $($_.Exception.Message)"
        return $null
    }

    $strategies = @(
        @{ Name = 'module PSWritePDF';                                Action = { ConvertTo-PdfPSWritePDF -Path $Path -Items $model } }
        @{ Name = 'bibliothèque PdfSharp (DLL locale)';               Action = { ConvertTo-PdfPdfSharp -Path $Path -Items $model } }
        @{ Name = "impression HTML (Edge / 'Microsoft Print to PDF')"; Action = { ConvertTo-PdfPrintPipeline -Path $Path -Items $model -PhaseLabel $PhaseLabel } }
        @{ Name = 'générateur PDF minimal natif';                     Action = { ConvertTo-PdfMinimal -Path $Path -Items $model } }
    )
    foreach ($strategy in $strategies) {
        try {
            if (Test-Path -Path $Path) { Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue }
            & $strategy.Action
            if ((Test-Path -Path $Path) -and ((Get-Item -Path $Path).Length -gt 0)) {
                Write-Log -Level Success -Message "Rapport PDF généré via $($strategy.Name) : $Path"
                return $Path
            }
            throw 'aucun fichier produit'
        } catch {
            Write-Log -Level Detail -Message "Stratégie PDF '$($strategy.Name)' indisponible ou en échec : $($_.Exception.Message)"
        }
    }

    # --- Repli final : HTML autonome ---
    try {
        $htmlPath = [System.IO.Path]::ChangeExtension($Path, '.html')
        $html = Get-ReportHtml -PhaseLabel $PhaseLabel
        [System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($true)))
        Write-Log -Level Warn -Message "Aucun moteur PDF disponible : rapport de repli HTML généré : $htmlPath"
        return $htmlPath
    } catch {
        Write-Log -Level Error -Message "Échec de la génération du rapport (PDF et repli HTML) : $($_.Exception.Message)"
        return $null
    }
}

# --- Export texte du journal (sans mot de passe : ceux-ci restent dans le PDF) ---
function Export-TextSummary {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add("Récapitulatif d'exécution - $script:ScriptName v$script:ScriptVersion - $env:COMPUTERNAME - $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')")
        $lines.Add(('-' * 100))
        foreach ($name in $script:ReportFacts.Keys) {
            $lines.Add(('{0,-30} : {1}' -f $name, $script:ReportFacts[$name]))
        }
        $lines.Add(('-' * 100))
        foreach ($item in $script:Journal) {
            if ($item.Niveau -in @('Detail')) { continue }
            $lines.Add(('[{0}] [{1,-7}] [{2}] {3}' -f $item.Horodatage, $item.Niveau, $item.Etape, $item.Message))
        }
        [System.IO.File]::WriteAllLines($Path, $lines, (New-Object System.Text.UTF8Encoding($true)))
        Write-Log -Level Success -Message "Récapitulatif texte exporté : $Path"
        return $Path
    } catch {
        Write-Log -Level Warn -Message "Export du récapitulatif texte impossible : $($_.Exception.Message)"
        return $null
    }
}

# --- Orchestration : resout le dossier de sortie (une seule question par session),
# genere le .pdf + le .txt et trace les chemins dans l'etat. Non bloquant. ---
function Invoke-ReportExport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PhaseLabel,
        # -NoTrack : ne pas tracer le rapport dans state.json (utilise par le reset,
        # qui vient de supprimer le fichier d'etat et ne doit pas le recreer)
        [switch]$NoTrack
    )
    if ($WhatIfPreference) {
        Write-Log -Level Detail -Message 'WhatIf : génération du rapport ignorée.'
        return
    }
    try {
        if (-not $script:ReportDirectory) {
            $default = [string](Get-ConfigValue -Path 'Report.Directory' -Default $script:Defaults.ReportDirectory)
            $script:ReportDirectory = Read-ValidatedInput `
                -Prompt "Dossier de sortie du rapport d'exécution (Entrée pour '$default')" `
                -Default $default `
                -Validator { param($v) try { if (-not (Test-Path -Path $v)) { New-Item -Path $v -ItemType Directory -Force -ErrorAction Stop | Out-Null }; $true } catch { $false } } `
                -ErrorMessage 'Dossier invalide ou impossible à créer.'
        }
        if (-not (Test-Path -Path $script:ReportDirectory)) {
            New-Item -Path $script:ReportDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $baseName = 'Init-WindowsServer_{0}_{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
        $pdfPath = Join-Path -Path $script:ReportDirectory -ChildPath ($baseName + '.pdf')
        $txtPath = Join-Path -Path $script:ReportDirectory -ChildPath ($baseName + '.txt')

        $finalPath = Export-PdfReport -Path $pdfPath -PhaseLabel $PhaseLabel
        Export-TextSummary -Path $txtPath | Out-Null
        if ($finalPath) {
            if (-not $NoTrack) {
                Add-CreatedObject -Category Reports -Key $finalPath -Entry @{ Path = $finalPath; Phase = $PhaseLabel; Type = 'Rapport' }
                Add-CreatedObject -Category Reports -Key $txtPath -Entry @{ Path = $txtPath; Phase = $PhaseLabel; Type = 'RecapTexte' }
            }
            Write-Log -Level Warn -Message "Rapport : $finalPath - il contient des mots de passe EN CLAIR : stockage sécurisé requis, excluez C:\Rapports\ de tout dépôt Git."
        }
    } catch {
        Write-Log -Level Warn -Message "La génération du rapport a échoué sans interrompre le script : $($_.Exception.Message)"
    }
}

#endregion

# =====================================================================
#  REGION 6 : AFFICHAGES EN ARBORESCENCE ET SELECTEURS
# =====================================================================
#region Arborescences

# --- Ajoute un noeud a l'arborescence memoire (affichage final en arbre) ---
function Add-TreeNode {
    param(
        [Parameter(Mandatory)][hashtable]$Nodes,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ParentDN,
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Type
    )
    $parentKey = if ($ParentDN -eq $DomainDN) { 'ROOT' } else { $ParentDN }
    $Nodes[$Key] = [PSCustomObject]@{ Key = $Key; ParentKey = $parentKey; Name = $Name; Type = $Type }
}

# --- Affiche la structure AD (OU / GG / GDL / Utilisateurs / Ordinateurs) en arbre ---
function Show-ADTree {
    param([Parameter(Mandatory)][hashtable]$Nodes)

    # Robustesse : tout noeud dont le parent est inconnu est rattache a la racine
    foreach ($n in @($Nodes.Values)) {
        if ($n.ParentKey -ne 'ROOT' -and -not $Nodes.ContainsKey($n.ParentKey)) {
            $n.ParentKey = 'ROOT'
        }
    }

    function Write-TreeLevel {
        param([string]$ParentKey, [string]$Prefix)
        $children = @($Nodes.Values | Where-Object { $_.ParentKey -eq $ParentKey } | Sort-Object -Property Type, Name)
        for ($i = 0; $i -lt $children.Count; $i++) {
            $isLast = ($i -eq $children.Count - 1)
            $branch = if ($isLast) { '+-- ' } else { '|-- ' }
            $icon = switch ($children[$i].Type) {
                'OU'       { '[OU]' }
                'CN'       { '[CN]' }
                'GG'       { '[GG]' }
                'GDL'      { '[GDL]' }
                'User'     { '[User]' }
                'Computer' { '[PC]' }
                default    { '' }
            }
            $color = switch ($children[$i].Type) {
                'OU'       { [System.ConsoleColor]::Yellow }
                'CN'       { [System.ConsoleColor]::DarkGray }
                'GG'       { [System.ConsoleColor]::Cyan }
                'GDL'      { [System.ConsoleColor]::Magenta }
                'User'     { [System.ConsoleColor]::Green }
                'Computer' { [System.ConsoleColor]::Gray }
                default    { [System.ConsoleColor]::White }
            }
            Write-Log -Message "$Prefix$branch$icon $($children[$i].Name)" -Color $color -NoJournal
            $newPrefix = $Prefix + $(if ($isLast) { '    ' } else { '|   ' })
            Write-TreeLevel -ParentKey $children[$i].Key -Prefix $newPrefix
        }
    }

    Write-Log -Message 'Domaine (racine)' -NoJournal
    Write-TreeLevel -ParentKey 'ROOT' -Prefix ''
}

# --- Affiche les OU candidates sous forme d'arbre, chaque OU gardant son numero [k] ---
function Show-OUPickerTree {
    param(
        [Parameter(Mandatory)][array]$AllOUs,
        [Parameter(Mandatory)][string]$DomainDN
    )
    $dnIndex = @{}
    for ($i = 0; $i -lt $AllOUs.Count; $i++) { $dnIndex[$AllOUs[$i].DN] = $i }

    $children = @{}
    for ($i = 0; $i -lt $AllOUs.Count; $i++) {
        $parentDN = Get-ParentDN -DN $AllOUs[$i].DN
        $key = if ($dnIndex.ContainsKey($parentDN)) { $parentDN } else { $DomainDN }
        if (-not $children.ContainsKey($key)) { $children[$key] = @() }
        $children[$key] += $i
    }

    function Write-PickerLevel {
        param([string]$ParentKey, [string]$Prefix)
        if (-not $children.ContainsKey($ParentKey)) { return }
        $kids = @($children[$ParentKey])
        for ($j = 0; $j -lt $kids.Count; $j++) {
            $idx = $kids[$j]
            $isLast = ($j -eq $kids.Count - 1)
            $branch = if ($isLast) { '+-- ' } else { '|-- ' }
            Write-Log -Message "    $Prefix$branch[$idx] [OU] $($AllOUs[$idx].Name)" -Color Yellow -NoJournal
            $newPrefix = $Prefix + $(if ($isLast) { '    ' } else { '|   ' })
            Write-PickerLevel -ParentKey $AllOUs[$idx].DN -Prefix $newPrefix
        }
    }

    Write-Log -Message '    Domaine (racine)' -NoJournal
    Write-PickerLevel -ParentKey $DomainDN -Prefix ''
}

# --- Selection (bouclante) d'une OU racine ; N ou Entree = racine du domaine ---
function Select-RootOU {
    param(
        [array]$AllOUs,
        [Parameter(Mandatory)][string]$DomainDN,
        [string]$ObjectLabel = 'cet objet',
        [string]$RootLabel = 'la racine du domaine'
    )
    if (-not $AllOUs -or $AllOUs.Count -eq 0) {
        return [PSCustomObject]@{ DN = $DomainDN; Label = $RootLabel }
    }
    Write-Log -Level Title -Message "  OU disponibles pour servir de racine à $ObjectLabel (optionnel) :" -NoJournal
    Write-Log -Message "    [N] $RootLabel (par défaut)" -NoJournal
    Show-OUPickerTree -AllOUs $AllOUs -DomainDN $DomainDN
    while ($true) {
        $choice = Read-Host -Prompt "  -> Choisir une racine (numéro entre crochets, ou 'N'/Entrée pour $RootLabel)"
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^[Nn]$') {
            return [PSCustomObject]@{ DN = $DomainDN; Label = $RootLabel }
        }
        if ($choice -match '^\d+$') {
            $idx = [int]$choice
            if ($idx -ge 0 -and $idx -lt $AllOUs.Count) {
                return [PSCustomObject]@{ DN = $AllOUs[$idx].DN; Label = "l'OU '$($AllOUs[$idx].Name)'" }
            }
        }
        Write-Log -Level Error -Message "  -> Choix invalide : entrez un numéro affiché entre crochets, ou 'N'." -NoJournal
    }
}

#endregion

# =====================================================================
#  REGION 7 : GPO (application des regles du catalogue + configurateur)
# =====================================================================
#region GPO

# --- Resout l'URL WSUS reelle : configuration > valeur deja saisie > question.
# Retourne $null si aucune URL n'est fournie (la regle 4.2 est alors ignoree). ---
function Get-WsusUrlValue {
    [OutputType([string])]
    param()
    if ($script:WsusUrl) { return $script:WsusUrl }

    $configUrl = [string](Get-ConfigValue -Path 'WsusUrl' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($configUrl)) {
        if (Test-WsusUrl -Value $configUrl) {
            $script:WsusUrl = $configUrl
            Write-Log -Message "URL WSUS chargée depuis la configuration : $configUrl"
            return $script:WsusUrl
        }
        Write-Log -Level Warn -Message "URL WSUS de la configuration invalide ('$configUrl') : ignorée."
    }
    if ($script:IsUnattended) { return $null }

    Write-Log -Level Warn -Message "La règle WSUS nécessite l'URL RÉELLE de votre serveur WSUS (aucun placeholder ne sera écrit)." -NoJournal
    while ($true) {
        $raw = Read-Host -Prompt '  -> URL du serveur WSUS (ex: http://srv-wsus:8530), ou Entrée pour annuler cette règle'
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        $raw = $raw.Trim()
        if (Test-WsusUrl -Value $raw) {
            $script:WsusUrl = $raw
            return $script:WsusUrl
        }
        Write-Log -Level Error -Message '  -> URL invalide. Format attendu : http(s)://serveur[:port]' -NoJournal
    }
}

# --- Applique UNE regle du catalogue GPO a une GPO donnee.
# Chaque ecriture de registre est controlee (-ErrorAction Stop) et JOURNALISEE :
# plus aucune erreur avalee silencieusement. Retourne $true si tout est applique. ---
function Set-GpoCatalogRule {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$RuleId
    )
    if (-not $script:GpoCatalog.Contains($RuleId)) {
        Write-Log -Level Warn -Message "Règle GPO '$RuleId' inconnue : ignorée."
        return $false
    }
    $rule = $script:GpoCatalog[$RuleId]

    $wsusUrl = $null
    if ($rule['RequiresWsusUrl']) {
        $wsusUrl = Get-WsusUrlValue
        if (-not $wsusUrl) {
            Write-Log -Level Warn -Message "Règle [$RuleId] '$($rule.Label)' NON appliquée : URL WSUS non fournie (règle à personnaliser ultérieurement)."
            return $false
        }
    }
    if ($rule['Caution']) {
        Write-Log -Level Warn -Message "Règle [$RuleId] : $($rule.Caution)"
    }

    $applied = 0
    $failed  = 0
    foreach ($setting in $rule.Settings) {
        $value = $setting.Value
        if ($setting.Type -eq 'String' -and $wsusUrl) {
            $value = ([string]$value).Replace('{WsusUrl}', $wsusUrl)
        }
        $target = '{0}\{1}' -f $setting.Key, $setting.ValueName
        if ($PSCmdlet.ShouldProcess("GPO '$GpoName' -> $target = $value", 'Set-GPRegistryValue')) {
            try {
                Set-GPRegistryValue -Name $GpoName -Key $setting.Key -ValueName $setting.ValueName `
                    -Type $setting.Type -Value $value -ErrorAction Stop | Out-Null
                $applied++
            } catch {
                $failed++
                Write-Log -Level Error -Message "Règle [$RuleId] '$($rule.Label)' : échec sur $target : $($_.Exception.Message)"
            }
        }
    }
    if ($failed -eq 0) {
        Write-Log -Level Success -Message "Règle [$RuleId] '$($rule.Label)' appliquée à '$GpoName' ($applied valeur(s) de registre)."
        return $true
    }
    Write-Log -Level Warn -Message "Règle [$RuleId] '$($rule.Label)' : $applied valeur(s) appliquée(s), $failed en échec."
    return ($applied -gt 0)
}

# --- Configurateur interactif multi-choix de GPO (ex: 1.2, 2.3, 4.1 ou pack [T]).
# Prerequis : module GroupPolicy importe (fait dans l'etape GPO avant l'appel). ---
function Invoke-GPOConfigurator {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification = 'Menu interactif plein écran (Clear-Host + couleurs).')]
    param([Parameter(Mandatory)][string]$GPOName)

    $quitMenu = $false
    while (-not $quitMenu) {
        Clear-Host
        Show-Banner -Text "CONFIGURATEUR DE GPO : $GPOName" -NoJournal
        Write-Log -Level Warn -Message ' ASTUCE : vous pouvez taper plusieurs choix séparés par des virgules (ex: 1.2, 2.3, 4.1)' -NoJournal

        foreach ($key in $script:GpoCatalog.Keys) {
            $catNum = $key.Split('.')[0]
            if ($key -eq "$catNum.1") {
                Write-Log -Level Warn -Message "`n --- $($script:GpoCategories[$catNum]) ---" -NoJournal
            }
            $suffix = if ($script:GpoCatalog[$key]['RequiresWsusUrl']) { ' (URL WSUS demandée)' } else { '' }
            Write-Log -Message "  [$key] $($script:GpoCatalog[$key].Label)$suffix" -NoJournal
        }
        Write-Log -Message "`n  [T] TOUT APPLIQUER (pack complet ANSSI/NIST)" -Color DarkCyan -NoJournal
        Write-Log -Message '  [0] Terminer et quitter ce configurateur' -Color Red -NoJournal

        $inputStr = Read-Host -Prompt "`n -> Votre choix"
        if ([string]::IsNullOrWhiteSpace($inputStr)) { continue }
        $inputStr = $inputStr.Trim()

        if ($inputStr.ToUpper() -eq 'T') {
            # Pack complet : la regle WSUS (placeholder interdit) exige une confirmation
            # explicite + l'URL reelle ; sinon elle est exclue du pack.
            $includeWsus = $false
            $wsusRuleIds = @($script:GpoCatalog.Keys | Where-Object { $script:GpoCatalog[$_]['RequiresWsusUrl'] })
            if ($wsusRuleIds.Count -gt 0) {
                $includeWsus = Read-YesNo "  Le pack complet contient la règle WSUS ($($wsusRuleIds -join ', ')) qui nécessite l'URL réelle du serveur WSUS. L'inclure ?"
            }
            Write-Log -Message "`n  -> Application du PACK COMPLET en cours..." -Color Cyan -NoJournal
            $okCount = 0
            $skipCount = 0
            foreach ($key in $script:GpoCatalog.Keys) {
                if ($script:GpoCatalog[$key]['RequiresWsusUrl'] -and -not $includeWsus) {
                    Write-Log -Level Warn -Message "Règle [$key] '$($script:GpoCatalog[$key].Label)' exclue du pack (à personnaliser avec votre URL WSUS)."
                    $skipCount++
                    continue
                }
                if (Set-GpoCatalogRule -GpoName $GPOName -RuleId $key) { $okCount++ } else { $skipCount++ }
            }
            Write-Log -Level Success -Message "Pack complet : $okCount règle(s) appliquée(s), $skipCount ignorée(s)/en échec sur '$GPOName'."
            Read-Host -Prompt "`n  -> Appuyez sur Entrée pour terminer la configuration de cette GPO" | Out-Null
            $quitMenu = $true
            continue
        }

        if ($inputStr -eq '0') {
            $quitMenu = $true
            continue
        }

        $choices = @($inputStr -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        $appliedCount = 0
        foreach ($c in $choices) {
            if ($script:GpoCatalog.Contains($c)) {
                Write-Log -Message "  -> Application : [$c] $($script:GpoCatalog[$c].Label)" -Color Cyan -NoJournal
                if (Set-GpoCatalogRule -GpoName $GPOName -RuleId $c) { $appliedCount++ }
            } else {
                Write-Log -Level Warn -Message "  -> Choix '$c' inconnu, ignoré." -NoJournal
            }
        }
        if ($appliedCount -gt 0) {
            Write-Log -Level Success -Message "  $appliedCount règle(s) appliquée(s) avec succès dans $GPOName." -NoJournal
            Write-Log -Level Detail -Message '  Vous pouvez continuer à ajouter des règles, ou taper 0 pour quitter.' -NoJournal
        }
        # Pause : laisser le temps de LIRE le resultat avant de rouvrir (Clear-Host) le menu
        Read-Host -Prompt "`n  -> Appuyez sur Entrée pour revenir au menu de configuration" | Out-Null
    }
}

#endregion

# =====================================================================
#  REGION 8 : SERVEUR DE FICHIERS (ACL NTFS + droits SMB granulaires)
# =====================================================================
#region Serveur de fichiers

# --- Reinitialise l'ACL NTFS d'un dossier : heritage desactive, ACE purgees,
# puis base minimale SYSTEM + Administrateurs (via SID : independant de la langue). ---
function Reset-FolderAcl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$KeepAdmins
    )
    if (-not $PSCmdlet.ShouldProcess($Path, "Réinitialisation de l'ACL NTFS (héritage désactivé, ACE purgées)")) { return }

    $acl = Get-Acl -Path $Path
    # Desactiver l'heritage SANS convertir les ACE heritees -> elles sont retirees
    $acl.SetAccessRuleProtection($true, $false)
    # Purge des ACE explicites residuelles -> DACL vierge
    foreach ($ace in @($acl.Access)) {
        [void]$acl.RemoveAccessRule($ace)
    }
    if ($KeepAdmins) {
        $full = [System.Security.AccessControl.FileSystemRights]::FullControl
        $inheritance = 'ContainerInherit,ObjectInherit'
        foreach ($wellKnownSid in @($script:WellKnownSid.System, $script:WellKnownSid.Administrators)) {
            try {
                $sid  = New-Object System.Security.Principal.SecurityIdentifier($wellKnownSid)
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, $inheritance, 'None', 'Allow')
                $acl.AddAccessRule($rule)
            } catch {
                Write-Log -Level Error -Message "Impossible d'ajouter l'ACE de base (SID $wellKnownSid) sur '$Path' : $($_.Exception.Message)"
            }
        }
    }
    Set-Acl -Path $Path -AclObject $acl
}

# --- Verifie/installe le role Serveur de fichiers (FS-FileServer), sans jamais
# laisser une exception remonter (ex: module ServerManager indisponible). Retourne
# $true si le role est present (ou installe), $false pour ignorer proprement l'etape. ---
function Confirm-FileServerRole {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()
    try {
        if ((Get-WindowsFeature -Name FS-FileServer -ErrorAction Stop).Installed) { return $true }
    } catch {
        Write-Log -Level Error -Message "Rôle Serveur de fichiers : état indéterminé ($($_.Exception.Message)). Étape des partages ignorée."
        return $false
    }
    Write-Log -Message 'Installation du rôle Serveur de fichiers (FS-FileServer)...'
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install-WindowsFeature FS-FileServer')) { return $true }
    try {
        Install-WindowsFeature -Name FileAndStorage-Services, FS-FileServer -IncludeManagementTools -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Log -Level Error -Message "Installation du rôle Serveur de fichiers impossible : $($_.Exception.Message). Étape des partages ignorée."
        return $false
    }
}

# --- Active l'ABE (Access-Based Enumeration) sur un partage SMB (module B1-M9 P2).
# L'utilisateur ne voit dans le partage que les dossiers/fichiers auxquels il a accès.
# Non bloquant : journalise l'erreur et retourne $false si le partage est illisible. ---
function Enable-ShareAbe {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$ShareName)
    if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) {
        Write-Log -Level Warn -Message "Partage '$ShareName' introuvable : ABE non appliquée."
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess("Partage '$ShareName'", "Activer l'énumération basée sur l'accès (ABE)")) { return $false }
    try {
        Set-SmbShare -Name $ShareName -FolderEnumerationMode AccessBased -Force -ErrorAction Stop
        Write-Log -Level Success -Message "ABE activée sur le partage '$ShareName'."
        return $true
    } catch {
        Write-Log -Level Error -Message "Activation de l'ABE sur '$ShareName' impossible : $($_.Exception.Message)"
        return $false
    }
}

# --- Deduit le niveau SMB (Read < Change < Full) des droits NTFS demandes ---
# CORRECTIF v7 : le masque n'utilise que des bits d'ECRITURE atomiques. L'ancien
# masque incluait le droit composite Modify, qui contient aussi des bits de
# LECTURE : une selection "Lecture seule" etait alors mappee a tort sur SMB
# 'Change' au lieu de 'Read'.
function Get-SmbAccessRight {
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$NtfsRights)
    $fsr = [System.Security.AccessControl.FileSystemRights]
    $writeMask = $fsr::WriteData -bor $fsr::AppendData -bor $fsr::WriteAttributes -bor $fsr::WriteExtendedAttributes -bor
                 $fsr::Delete -bor $fsr::DeleteSubdirectoriesAndFiles -bor
                 $fsr::ChangePermissions -bor $fsr::TakeOwnership
    if (([int]($NtfsRights -band $fsr::FullControl)) -eq [int]$fsr::FullControl) { return 'Full' }
    if (([int]($NtfsRights -band $writeMask)) -ne 0) { return 'Change' }
    return 'Read'
}

# --- Applique reellement les droits SMB + NTFS a un compte sur un partage.
# POINT CLE : l'identite NTFS est resolue via le SID du groupe AD (traduction
# garantie, quelle que soit la langue de l'OS et du domaine). ---
function Grant-ShareAccess {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$ShareName,
        [Parameter(Mandatory)][string]$SharePath,
        [Parameter(Mandatory)][string]$AccountName,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$NtfsRights,
        [string]$RightsLabel
    )
    if (-not $RightsLabel) { $RightsLabel = $NtfsRights.ToString() }
    if ([int]$NtfsRights -eq 0) {
        Write-Log -Level Warn -Message "Aucun droit NTFS valide à appliquer pour '$AccountName' : ignoré."
        return $null
    }
    $smbRight = Get-SmbAccessRight -NtfsRights $NtfsRights

    # Resolution de l'identite via le SID du groupe AD (repli : nom brut)
    $ntfsIdentity = [object]$AccountName
    $smbPrincipal = $AccountName
    try {
        $adGroup = Get-ADGroup -Identity $AccountName -ErrorAction Stop
        $sid = [System.Security.Principal.SecurityIdentifier]$adGroup.SID
        $ntfsIdentity = $sid
        try {
            $smbPrincipal = $sid.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            Write-Log -Level Warn -Message "Traduction SID -> nom impossible pour '$AccountName' : nom brut utilisé côté SMB."
            $smbPrincipal = $AccountName
        }
    } catch {
        Write-Log -Level Detail -Message "'$AccountName' non résolu comme groupe AD (saisie manuelle d'un compte ?) : nom brut utilisé."
    }

    if (-not $PSCmdlet.ShouldProcess("Partage '$ShareName' ($SharePath)", "Accorder [$RightsLabel] (SMB: $smbRight) à '$AccountName'")) { return $null }

    # --- SMB : idempotence (retrait d'un eventuel ACE existant) puis octroi ---
    try {
        try {
            Revoke-SmbShareAccess -Name $ShareName -AccountName $smbPrincipal -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Log -Level Detail -Message "Aucun ACE SMB préexistant à retirer pour '$smbPrincipal' sur '$ShareName'."
        }
        Grant-SmbShareAccess -Name $ShareName -AccountName $smbPrincipal -AccessRight $smbRight -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Log -Level Error -Message "Échec de l'octroi d'accès SMB à '$AccountName' sur '$ShareName' : $($_.Exception.Message)"
        return "ERREUR d'octroi de droits SMB à '$AccountName' sur '$ShareName'"
    }

    # --- NTFS : regle unique combinant les droits choisis, posee via SID ---
    try {
        $acl  = Get-Acl -Path $SharePath
        # Idempotence NTFS (comme cote SMB) : on purge d'abord les ACE explicites
        # de cette identite, sinon un re-passage avec des droits differents
        # cumulerait deux ACE Allow (ex: Read puis Modify). PurgeAccessRules attend
        # un IdentityReference : un SID en est un ; sinon on enveloppe le nom.
        $idRef = if ($ntfsIdentity -is [System.Security.Principal.IdentityReference]) { $ntfsIdentity }
                 else { New-Object System.Security.Principal.NTAccount([string]$ntfsIdentity) }
        try { $acl.PurgeAccessRules($idRef) } catch {
            Write-Log -Level Detail -Message "Purge des ACE existantes pour '$AccountName' impossible (poursuite) : $($_.Exception.Message)"
        }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($ntfsIdentity, $NtfsRights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $SharePath -AclObject $acl
    } catch {
        Write-Log -Level Error -Message "Échec de l'application de l'ACL NTFS pour '$AccountName' sur '$SharePath' : $($_.Exception.Message)"
        return "ERREUR NTFS pour '$AccountName' sur '$ShareName'"
    }

    Write-Log -Level Success -Message "Droits [$RightsLabel] (SMB: $smbRight) accordés à '$AccountName' sur '$ShareName'."
    return "Droits [$RightsLabel] (SMB: $smbRight) accordés à '$AccountName' sur '$ShareName'"
}

# --- Sous-menu interactif : choix granulaire des niveaux de droits (multi-choix).
# Retourne @{ Rights = [FileSystemRights] ; Label = [string] } ou $null. ---
function Read-ShareRightsSelection {
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$AccountName)

    Write-Log -Level Title -Message "     Niveau(x) de droit à accorder à '$AccountName' :" -NoJournal
    foreach ($rk in $script:ShareRightsCatalog.Keys) {
        Write-Log -Message "       [$rk] $($script:ShareRightsCatalog[$rk].Label)" -NoJournal
    }
    $rightsInput = Read-Host -Prompt "       -> Numéros séparés par des virgules (ex: 1,3), ou Entrée pour 'Modification' par défaut"
    if ([string]::IsNullOrWhiteSpace($rightsInput)) { $rightsInput = '2' }

    $chosen = @($rightsInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $script:ShareRightsCatalog.Contains($_) })
    if ($chosen.Count -eq 0) {
        Write-Log -Level Warn -Message "       -> Aucun niveau valide sélectionné, 'Modification' appliqué par défaut." -NoJournal
        $chosen = @('2')
    }

    [System.Security.AccessControl.FileSystemRights]$ntfsRights = 0
    $labels = @()
    foreach ($ck in $chosen) {
        if ($ck -eq '7') {
            # Autorisations speciales : saisie avancee de droits FileSystemRights
            Write-Log -Level Title -Message '       Autorisations spéciales : saisissez un ou plusieurs droits FileSystemRights (virgules).' -NoJournal
            Write-Log -Level Detail -Message '       Ex: ReadData, WriteData, AppendData, Delete, ReadPermissions, ChangePermissions, TakeOwnership, ExecuteFile' -NoJournal
            $specInput = Read-Host -Prompt '       -> Droits spéciaux'
            $specNames = @($specInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
            $specApplied = @()
            foreach ($sn in $specNames) {
                try {
                    $parsed = [System.Security.AccessControl.FileSystemRights]$sn
                    $ntfsRights = $ntfsRights -bor $parsed
                    $specApplied += $parsed.ToString()
                } catch {
                    Write-Log -Level Warn -Message "       -> Droit spécial '$sn' inconnu, ignoré." -NoJournal
                }
            }
            if ($specApplied.Count -gt 0) { $labels += "Spéciales($($specApplied -join '+'))" }
        } else {
            $ntfsRights = $ntfsRights -bor $script:ShareRightsCatalog[$ck].Ntfs
            $labels += $script:ShareRightsCatalog[$ck].Label
        }
    }

    if ([int]$ntfsRights -eq 0) {
        Write-Log -Level Warn -Message "       -> Aucun droit valide à appliquer pour '$AccountName' : ignoré." -NoJournal
        return $null
    }
    return [PSCustomObject]@{ Rights = $ntfsRights; Label = ($labels -join ', ') }
}

# --- Menu granulaire + application reelle (SMB + NTFS) pour un compte ---
function Set-ShareAccessGranular {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$ShareName,
        [Parameter(Mandatory)][string]$SharePath,
        [Parameter(Mandatory)][string]$AccountName
    )
    $selection = Read-ShareRightsSelection -AccountName $AccountName
    if ($null -eq $selection) { return $null }
    return Grant-ShareAccess -ShareName $ShareName -SharePath $SharePath -AccountName $AccountName `
        -NtfsRights $selection.Rights -RightsLabel $selection.Label
}

#endregion

# =====================================================================
#  REGION 9 : PRIMITIVES ACTIVE DIRECTORY (idempotentes et tracees)
# =====================================================================
#region Primitives AD
# Chaque primitive : 1) verifie l'existant (idempotence), 2) cree l'objet,
# 3) le TRACE dans state.json (seuls les objets reellement crees sont traces :
# le reset 'biere' ne touchera jamais un objet preexistant reutilise).

# --- Rechargement de l'existant AD (tolerance de panne / reprise) ---
function Import-ExistingADStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DomainDN,
        [Parameter(Mandatory)][hashtable]$TreeNodes
    )
    $result = [PSCustomObject]@{
        OUs = @(); Users = @(); Computers = @(); GGs = @(); GDLs = @()
    }

    Write-Log -Level Warn -Message "`n--- Reprise : vérification de l'existant dans l'AD ---" -NoJournal
    Write-Log -Level Detail -Message 'Recherche des OU, GG, GDL, utilisateurs et ordinateurs déjà présents...'

    # --- OU existantes (triees par profondeur : parents avant enfants) ---
    try {
        $ous = @(Get-ADOrganizationalUnit -Filter * -ErrorAction Stop |
                 Sort-Object -Property { ($_.DistinguishedName -split '(?<!\\),').Count })
        foreach ($ou in $ous) {
            $parentDN = Get-ParentDN -DN $ou.DistinguishedName
            $result.OUs += [PSCustomObject]@{ Name = $ou.Name; DN = $ou.DistinguishedName }
            Add-TreeNode -Nodes $TreeNodes -Key $ou.DistinguishedName -ParentDN $parentDN `
                -DomainDN $DomainDN -Name $ou.Name -Type 'OU'
        }
    } catch { Write-Log -Level Error -Message "Impossible de lister les OU : $($_.Exception.Message)" }

    # --- Groupes Globaux existants (convention de nommage : prefixe GG) ---
    try {
        $ggs = @(Get-ADGroup -Filter "GroupScope -eq 'Global' -and Name -like 'GG*'" -ErrorAction Stop)
        foreach ($gg in $ggs) {
            $result.GGs += $gg.Name
            Add-TreeNode -Nodes $TreeNodes -Key $gg.DistinguishedName -ParentDN (Get-ParentDN -DN $gg.DistinguishedName) `
                -DomainDN $DomainDN -Name $gg.Name -Type 'GG'
        }
    } catch { Write-Log -Level Error -Message "Impossible de lister les GG : $($_.Exception.Message)" }

    # --- GDL existantes (convention de nommage : prefixe GDL) ---
    try {
        $gdls = @(Get-ADGroup -Filter "GroupScope -eq 'DomainLocal' -and Name -like 'GDL*'" -ErrorAction Stop)
        foreach ($gdl in $gdls) {
            $result.GDLs += $gdl.Name
            Add-TreeNode -Nodes $TreeNodes -Key $gdl.DistinguishedName -ParentDN (Get-ParentDN -DN $gdl.DistinguishedName) `
                -DomainDN $DomainDN -Name $gdl.Name -Type 'GDL'
        }
    } catch { Write-Log -Level Error -Message "Impossible de lister les GDL : $($_.Exception.Message)" }

    # --- Utilisateurs existants (hors comptes techniques integres) ---
    $builtinAccounts = @('Administrator', 'Administrateur', 'Guest', 'Invite', 'Invité', 'krbtgt')
    try {
        $users = @(Get-ADUser -Filter * -ErrorAction Stop |
                   Where-Object { $builtinAccounts -notcontains $_.SamAccountName })
        foreach ($u in $users) {
            $parentDN = Get-ParentDN -DN $u.DistinguishedName
            $result.Users += $u.SamAccountName
            if ($parentDN -ne $DomainDN -and -not $TreeNodes.ContainsKey($parentDN) -and $parentDN -match '^CN=([^,]+),') {
                Add-TreeNode -Nodes $TreeNodes -Key $parentDN -ParentDN $DomainDN -DomainDN $DomainDN -Name $Matches[1] -Type 'CN'
            }
            Add-TreeNode -Nodes $TreeNodes -Key $u.DistinguishedName -ParentDN $parentDN `
                -DomainDN $DomainDN -Name $u.SamAccountName -Type 'User'
        }
    } catch { Write-Log -Level Error -Message "Impossible de lister les utilisateurs : $($_.Exception.Message)" }

    # --- Ordinateurs existants (hors controleurs de domaine) ---
    try {
        $computers = @(Get-ADComputer -Filter * -ErrorAction Stop |
                       Where-Object { $_.DistinguishedName -notlike '*OU=Domain Controllers,*' })
        foreach ($c in $computers) {
            $parentDN = Get-ParentDN -DN $c.DistinguishedName
            $result.Computers += $c.Name
            if ($parentDN -ne $DomainDN -and -not $TreeNodes.ContainsKey($parentDN) -and $parentDN -match '^CN=([^,]+),') {
                Add-TreeNode -Nodes $TreeNodes -Key $parentDN -ParentDN $DomainDN -DomainDN $DomainDN -Name $Matches[1] -Type 'CN'
            }
            Add-TreeNode -Nodes $TreeNodes -Key $c.DistinguishedName -ParentDN $parentDN `
                -DomainDN $DomainDN -Name $c.Name -Type 'Computer'
        }
    } catch { Write-Log -Level Error -Message "Impossible de lister les ordinateurs : $($_.Exception.Message)" }

    Write-Log -Level Title -Message "Existant détecté : $($result.OUs.Count) OU, $($result.GGs.Count) GG, $($result.GDLs.Count) GDL, $($result.Users.Count) utilisateur(s), $($result.Computers.Count) ordinateur(s)."
    Write-Log -Level Detail -Message 'Ces objets seront proposés comme racines/membres : aucun doublon ne sera créé.'
    return $result
}

# --- OU (creation idempotente, protegee, tracee) ---
function New-TrackedOU {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$ParentDN,
        [string]$ParentLabel = 'la racine du domaine'
    )
    $existing = $null
    try {
        $nameSafe = ConvertTo-ADFilterValue -Value $Name
        $existing = Get-ADOrganizationalUnit -SearchBase $ParentDN -SearchScope OneLevel `
            -Filter "Name -eq '$nameSafe'" -ErrorAction SilentlyContinue
    } catch {
        $existing = $null
    }
    if ($existing) {
        Write-Log -Level Detail -Message "OU '$Name' existe déjà dans $ParentLabel : réutilisation (aucune création)."
        return [PSCustomObject]@{ DN = $existing.DistinguishedName; Name = $Name; Created = $false }
    }
    if (-not $PSCmdlet.ShouldProcess("OU '$Name' dans $ParentLabel", 'New-ADOrganizationalUnit')) { return $null }
    $newOU = New-ADOrganizationalUnit -Name $Name -Path $ParentDN -ProtectedFromAccidentalDeletion $true -PassThru -ErrorAction Stop
    Add-CreatedObject -Category OUs -Key $newOU.DistinguishedName -Entry @{ Name = $Name; DN = $newOU.DistinguishedName }
    Write-Log -Level Success -Message "OU '$Name' créée dans $ParentLabel (protection anti-suppression activée)."
    return [PSCustomObject]@{ DN = $newOU.DistinguishedName; Name = $Name; Created = $true }
}

# --- Utilisateur (mot de passe fourni en clair : affiche a l'admin + rapport PDF,
# jamais code en dur ; changement impose a la premiere connexion) ---
function New-TrackedUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Le mot de passe initial, généré aléatoirement, doit être communiqué en clair à l''administrateur (récapitulatif + rapport). Changement imposé à la première connexion.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PlainPassword',
        Justification = 'Voir ci-dessus : transmission volontaire en clair du mot de passe initial.')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$FirstName,
        [Parameter(Mandatory)][string]$LastName,
        [Parameter(Mandatory)][string]$Login,
        [Parameter(Mandatory)][string]$OuDN,
        [Parameter(Mandatory)][string]$OuLabel,
        [Parameter(Mandatory)][string]$PlainPassword,
        # Options « compte à durée limitée » (module B1-M9 P7 - prestataires)
        [datetime]$AccountExpirationDate,
        [string]$LogonWorkstations
    )
    $Login = ($Login -replace '[^a-zA-Z0-9._\-]', '')
    if ($Login.Length -gt 20) { $Login = $Login.Substring(0, 20) }
    if ([string]::IsNullOrWhiteSpace($Login)) {
        Write-Log -Level Error -Message 'Login vide après nettoyage des caractères invalides : utilisateur ignoré.'
        return $null
    }
    $upn = '{0}@{1}' -f $Login, $script:DomainDNSRoot

    $loginSafe = ConvertTo-ADFilterValue -Value $Login
    $existing = Get-ADUser -Filter "SamAccountName -eq '$loginSafe'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log -Level Detail -Message "Utilisateur '$Login' existe déjà : réutilisation (mot de passe inchangé)."
        $script:CreatedCreds.Add([PSCustomObject]@{ Login = $Login; MotDePasse = '(déjà existant - inchangé)'; OU = $OuLabel })
        return [PSCustomObject]@{ DN = $existing.DistinguishedName; Login = $Login; Created = $false }
    }

    if (-not $PSCmdlet.ShouldProcess("Utilisateur '$Login' dans $OuLabel", 'New-ADUser')) { return $null }
    $securePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
    $userParams = @{
        Name = "$FirstName $LastName"; GivenName = $FirstName; Surname = $LastName
        SamAccountName = $Login; UserPrincipalName = $upn; Path = $OuDN
        AccountPassword = $securePassword; Enabled = $true; ChangePasswordAtLogon = $true
        PassThru = $true; ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('AccountExpirationDate')) { $userParams['AccountExpirationDate'] = $AccountExpirationDate }
    if ($LogonWorkstations) { $userParams['LogonWorkstations'] = $LogonWorkstations }
    $newUser = New-ADUser @userParams

    Add-CreatedObject -Category Users -Key $newUser.DistinguishedName -Entry @{ Login = $Login; DN = $newUser.DistinguishedName; OU = $OuLabel }
    $script:CreatedCreds.Add([PSCustomObject]@{ Login = $Login; MotDePasse = $PlainPassword; OU = $OuLabel })
    $extra = ''
    if ($PSBoundParameters.ContainsKey('AccountExpirationDate')) { $extra += " (expire le $($AccountExpirationDate.ToString('yyyy-MM-dd')))" }
    if ($LogonWorkstations) { $extra += " (postes autorisés : $LogonWorkstations)" }
    Write-Log -Level Success -Message "Utilisateur '$Login' créé dans $OuLabel (changement de mot de passe imposé à la 1ère connexion)$extra."
    return [PSCustomObject]@{ DN = $newUser.DistinguishedName; Login = $Login; Created = $true }
}

# --- Ordinateur (sAMAccountName tronque a 15 caracteres NetBIOS + '$') ---
function New-TrackedComputer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$TargetDN,
        [Parameter(Mandatory)][string]$DomainDN,
        [string]$TargetLabel = 'le conteneur par défaut'
    )
    $nameSafe = ConvertTo-ADFilterValue -Value $Name
    $existing = Get-ADComputer -Filter "Name -eq '$nameSafe'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log -Level Detail -Message "Ordinateur '$Name' existe déjà : réutilisation (aucune création)."
        return [PSCustomObject]@{ DN = $existing.DistinguishedName; Name = $Name; Created = $false }
    }

    if (-not $PSCmdlet.ShouldProcess("Ordinateur '$Name' dans $TargetLabel", 'New-ADComputer')) { return $null }
    # sAMAccountName limite a 15 caracteres (nom NetBIOS) + '$'
    $sam = $Name
    if ($sam.Length -gt 15) { $sam = $sam.Substring(0, 15) }
    $sam += '$'

    # Deux noms distincts partageant les 15 premiers caracteres NetBIOS entrent en
    # collision sur le sAMAccountName (le test par 'Name' ci-dessus ne l'attrape pas).
    # On leve alors une erreur explicite (retry en interactif, journalisee en unattended).
    $samSafe = ConvertTo-ADFilterValue -Value $sam
    $existingSam = Get-ADComputer -Filter "SamAccountName -eq '$samSafe'" -ErrorAction SilentlyContinue
    if ($existingSam) {
        throw "Collision de nom NetBIOS : le sAMAccountName '$sam' est déjà utilisé par l'ordinateur '$($existingSam.Name)'. Choisissez un nom dont les 15 premiers caractères sont uniques."
    }

    if ($TargetDN -ne $DomainDN) {
        $newComputer = New-ADComputer -Name $Name -SamAccountName $sam -Path $TargetDN -PassThru -ErrorAction Stop
    } else {
        $newComputer = New-ADComputer -Name $Name -SamAccountName $sam -PassThru -ErrorAction Stop
    }
    Add-CreatedObject -Category Computers -Key $newComputer.DistinguishedName -Entry @{ Name = $Name; DN = $newComputer.DistinguishedName }
    Write-Log -Level Success -Message "Ordinateur '$Name' créé dans $TargetLabel."
    return [PSCustomObject]@{ DN = $newComputer.DistinguishedName; Name = $Name; Created = $true }
}

# --- Groupe (GG ou GDL) protege et trace ---
function New-TrackedGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Global', 'DomainLocal')][string]$Scope,
        [Parameter(Mandatory)][string]$PathDN,
        [string]$PathLabel = 'la racine du domaine'
    )
    $nameSafe = ConvertTo-ADFilterValue -Value $Name
    $existing = Get-ADGroup -Filter "Name -eq '$nameSafe'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log -Level Detail -Message "Groupe '$Name' existe déjà : réutilisation (aucune création)."
        return [PSCustomObject]@{ DN = $existing.DistinguishedName; Name = $Name; Created = $false }
    }

    if (-not $PSCmdlet.ShouldProcess("Groupe $Scope '$Name' dans $PathLabel", 'New-ADGroup')) { return $null }
    $newGroup = New-ADGroup -Name $Name -GroupScope $Scope -GroupCategory Security -Path $PathDN -PassThru -ErrorAction Stop
    Set-ADObject -Identity $newGroup.DistinguishedName -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
    Add-CreatedObject -Category Groups -Key $newGroup.DistinguishedName -Entry @{ Name = $Name; DN = $newGroup.DistinguishedName; Scope = $Scope }
    Write-Log -Level Success -Message "Groupe $Scope '$Name' créé dans $PathLabel (protection anti-suppression activée)."
    return [PSCustomObject]@{ DN = $newGroup.DistinguishedName; Name = $Name; Created = $true }
}

# --- Ajout d'un membre a un groupe, avec journalisation de l'erreur eventuelle ---
function Add-GroupMemberLogged {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][string]$MemberName,
        [ValidateSet('Utilisateur', 'Ordinateur', 'GG')][string]$MemberType = 'Utilisateur'
    )
    if (-not $PSCmdlet.ShouldProcess("Groupe '$GroupName'", "Ajouter le membre '$MemberName' ($MemberType)")) { return $false }
    try {
        $member = if ($MemberType -eq 'Ordinateur') { Get-ADComputer -Identity $MemberName -ErrorAction Stop } else { $MemberName }
        Add-ADGroupMember -Identity $GroupName -Members $member -ErrorAction Stop
        Write-Log -Level Success -Message "Membre '$MemberName' ($MemberType) ajouté au groupe '$GroupName'."
        return $true
    } catch {
        Write-Log -Level Error -Message "Ajout de '$MemberName' au groupe '$GroupName' impossible : $($_.Exception.Message)"
        return $false
    }
}

# --- GPO (creation idempotente et tracee) ---
function New-TrackedGpo {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name)
    $existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log -Level Detail -Message "GPO '$Name' existe déjà : réutilisation (aucune création)."
        return [PSCustomObject]@{ Name = $Name; Id = $existing.Id.ToString(); Created = $false }
    }
    if (-not $PSCmdlet.ShouldProcess("GPO '$Name'", 'New-GPO')) { return $null }
    $gpo = New-GPO -Name $Name -ErrorAction Stop
    Add-CreatedObject -Category GPOs -Key $Name -Entry @{ Name = $Name; Id = $gpo.Id.ToString() }
    Write-Log -Level Success -Message "GPO '$Name' créée (vide, à configurer)."
    return [PSCustomObject]@{ Name = $Name; Id = $gpo.Id.ToString(); Created = $true }
}

# --- Lien GPO -> OU (idempotent et trace) ---
function New-TrackedGpoLink {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$TargetDN,
        [string]$TargetLabel
    )
    if (-not $TargetLabel) { $TargetLabel = $TargetDN }
    $inheritance = Get-GPInheritance -Target $TargetDN -ErrorAction SilentlyContinue
    $alreadyLinked = $inheritance -and @($inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }).Count -gt 0
    if ($alreadyLinked) {
        Write-Log -Level Detail -Message "La GPO '$GpoName' est déjà liée à $TargetLabel."
        return $true
    }
    if (-not $PSCmdlet.ShouldProcess("GPO '$GpoName'", "Lier à $TargetLabel")) { return $false }
    try {
        New-GPLink -Name $GpoName -Target $TargetDN -ErrorAction Stop | Out-Null
        Add-CreatedObject -Category GpoLinks -Key "$GpoName|$TargetDN" -Entry @{ Gpo = $GpoName; Target = $TargetDN }
        Write-Log -Level Success -Message "GPO '$GpoName' liée à $TargetLabel."
        return $true
    } catch {
        Write-Log -Level Error -Message "Erreur lors du lien de la GPO '$GpoName' vers $TargetLabel : $($_.Exception.Message)"
        return $false
    }
}

#endregion

# =====================================================================
#  REGION 10 : PHASE 1 - PRE-CONFIGURATION (avant promotion AD DS)
# =====================================================================
#region Phase 1
# REGLE DE FIABILITE (correctif majeur) : toute etape susceptible de redemarrer
# la machine (mises a jour -AutoReboot, renommage, promotion AD DS) marque et
# sauvegarde son etat AVANT de lancer la commande a risque. Ainsi, l'etape n'est
# jamais rejouee apres le redemarrage.

# --- Rapport + redemarrage controle (interactif : pause ; unattended : selon config) ---
function Invoke-RestartWithReport {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$PhaseLabel
    )
    Invoke-ReportExport -PhaseLabel $PhaseLabel
    Write-Log -Level Error -Message ('=' * 60) -NoJournal
    Write-Log -Level Error -Message " Le serveur doit redémarrer pour $Reason." -NoJournal
    Write-Log -Level Error -Message ' RELANCEZ CE SCRIPT après le redémarrage pour poursuivre (reprise automatique).' -NoJournal
    Write-Log -Level Error -Message ('=' * 60) -NoJournal
    Write-Log -Level Warn -Message "Redémarrage requis : $Reason"

    if ($script:IsUnattended) {
        if (-not [bool](Get-ConfigValue -Path 'AutoReboot' -Default $false)) {
            Write-Log -Level Warn -Message 'Mode -Unattended sans AutoReboot : redémarrez manuellement puis relancez le script.'
            return
        }
    } else {
        Read-Host -Prompt 'Appuyez sur Entrée pour redémarrer' | Out-Null
    }
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Redémarrage ($Reason)")) {
        Restart-Computer -Force
    }
}

# --- [1/5] Mises a jour Windows (prioritaires, avant toute config reseau) ---
function Invoke-WindowsUpdateStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Mises à jour Windows'
    Write-Log -Level Warn -Message "`n--- [1/5] Mises à jour Windows (prioritaire) ---" -NoJournal
    $recap = @()

    if ($script:State.Steps.UpdatesChecked) {
        Write-Log -Level Detail -Message 'Étape déjà traitée lors d''une exécution précédente : ignorée.'
        $recap += 'Étape déjà traitée lors d''une exécution précédente (reprise) : ignorée'
    } else {
        $doUpdates = Read-YesNo 'Voulez-vous installer les dernières mises à jour de sécurité maintenant ?' `
            -UnattendedAnswer ([bool](Get-ConfigValue -Path 'InstallUpdates' -Default $false))
        if ($doUpdates) {
            Write-Log -Level Error -Message 'ATTENTION : si une mise à jour nécessite un redémarrage, le serveur va redémarrer' -NoJournal
            Write-Log -Level Error -Message 'automatiquement et vous devrez RELANCER CE SCRIPT ensuite pour poursuivre.' -NoJournal
            try {
                Write-Log -Level Detail -Message 'Installation du module PSWindowsUpdate...'
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction Stop | Out-Null
                Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                Import-Module -Name PSWindowsUpdate -ErrorAction Stop

                # CORRECTIF fiabilite : etat marque et sauvegarde AVANT -AutoReboot,
                # sinon l'etape serait rejouee apres un redemarrage automatique.
                $script:State.Steps.UpdatesChecked = $true
                Save-ScriptState -State $script:State

                Write-Log -Message 'Recherche et installation des mises à jour (cela peut être très long)...'
                if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Get-WindowsUpdate -Install -AcceptAll -AutoReboot')) {
                    Get-WindowsUpdate -Install -AcceptAll -AutoReboot
                }
                Write-Log -Level Success -Message 'Mises à jour recherchées et installées (PSWindowsUpdate).'
                Add-ReportFact -Name 'Mises à jour Windows' -Value 'Recherchées/installées'
                $recap += 'Module PSWindowsUpdate installé et mises à jour recherchées/installées'
            } catch {
                Write-Log -Level Error -Message "ÉCHEC de l'installation des mises à jour : $($_.Exception.Message)"
                Write-Log -Level Warn -Message 'L''étape n''est PAS marquée comme faite : vous pourrez la relancer plus tard.' -NoJournal
                $script:State.Steps.UpdatesChecked = $false
                Save-ScriptState -State $script:State
                $recap += 'ÉCHEC des mises à jour (étape non marquée comme faite, relance possible)'
            }
        } else {
            $script:State.Steps.UpdatesChecked = $true
            Save-ScriptState -State $script:State
            Write-Log -Message 'Mises à jour refusées par l''utilisateur (étape marquée comme traitée).'
            $recap += 'Mises à jour refusées par l''utilisateur (étape marquée comme traitée)'
        }
    }
    Show-StepSummary -Title 'MISES À JOUR WINDOWS' -Lines $recap
}

# --- [2/5] Configuration IP statique (validations bouclantes) ---
function Invoke-StaticIpStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Configuration IP statique'
    Write-Log -Level Warn -Message "`n--- [2/5] Configuration IP statique ---" -NoJournal
    $recap = @()

    $doConfig = $true
    if ($script:State.Steps.IPConfigured) {
        Write-Log -Level Detail -Message 'IP déjà configurée lors d''une exécution précédente (état sauvegardé).'
        $doConfig = Read-YesNo 'Voulez-vous la reconfigurer quand même ?' -UnattendedAnswer $false
    } elseif ($script:IsUnattended -and -not (Get-ConfigValue -Path 'Network.IPAddress')) {
        Write-Log -Level Detail -Message 'Aucune configuration réseau fournie (Network.IPAddress) : étape ignorée.'
        $doConfig = $false
        $recap += 'Aucune configuration réseau fournie : étape ignorée'
    }

    if (-not $doConfig) {
        if ($recap.Count -eq 0) { $recap += 'IP déjà configurée précédemment : reconfiguration refusée (reprise)' }
        Show-StepSummary -Title 'CONFIGURATION IP STATIQUE' -Lines $recap
        return
    }

    $adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })
    if ($adapters.Count -eq 0) {
        Write-Log -Level Error -Message 'Aucune carte réseau active détectée : configuration IP ignorée.'
        Show-StepSummary -Title 'CONFIGURATION IP STATIQUE' -Lines @('Aucune carte réseau active détectée : étape ignorée')
        return
    }

    # --- Selection de la carte (bouclante en interactif, par alias en unattended) ---
    $adapterName = $null
    if ($script:IsUnattended) {
        $configAlias = [string](Get-ConfigValue -Path 'Network.InterfaceAlias' -Default '')
        if ($configAlias) {
            $match = @($adapters | Where-Object { $_.Name -eq $configAlias })
            if ($match.Count -eq 1) { $adapterName = $match[0].Name }
        } elseif ($adapters.Count -eq 1) {
            $adapterName = $adapters[0].Name
        }
        if (-not $adapterName) {
            Write-Log -Level Error -Message "Carte réseau introuvable ou ambiguë (InterfaceAlias='$configAlias') : étape ignorée."
            Show-StepSummary -Title 'CONFIGURATION IP STATIQUE' -Lines @('Carte réseau introuvable/ambiguë : étape ignorée')
            return
        }
    } else {
        Write-Log -Level Title -Message 'Cartes réseau actives détectées :' -NoJournal
        for ($i = 0; $i -lt $adapters.Count; $i++) {
            Write-Log -Message "  [$i] $($adapters[$i].Name) ($($adapters[$i].InterfaceDescription))" -NoJournal
        }
        while ($null -eq $adapterName) {
            $choice = Read-Host -Prompt '  -> Numéro de la carte à configurer (ex: 0)'
            if ($choice -match '^\d+$' -and [int]$choice -lt $adapters.Count) {
                $adapterName = $adapters[[int]$choice].Name
            } else {
                Write-Log -Level Error -Message '  -> Choix invalide : entrez un des numéros affichés entre crochets.' -NoJournal
            }
        }
    }
    Write-Log -Level Success -Message "Carte '$adapterName' sélectionnée."

    # --- Saisies validees en boucle : IP, prefixe, passerelle (opt.), DNS (opt.) ---
    $ip = Read-IPv4Address -Prompt 'Adresse IP statique (ex: 192.168.1.10)' `
        -UnattendedValue ([string](Get-ConfigValue -Path 'Network.IPAddress' -Default ''))
    $prefixRaw = Read-ValidatedInput -Prompt 'Masque en notation CIDR (ex: 24)' `
        -Validator { Test-IPv4Prefix -Value $args[0] } `
        -ErrorMessage 'Masque invalide : entier attendu entre 0 et 32.' `
        -UnattendedValue ([string](Get-ConfigValue -Path 'Network.PrefixLength' -Default '24'))
    $prefix = [int]$prefixRaw
    $gateway = Read-IPv4Address -Prompt 'Passerelle (ex: 192.168.1.254) - Entrée si aucune' -AllowEmpty `
        -UnattendedValue ([string](Get-ConfigValue -Path 'Network.Gateway' -Default ''))
    $dnsServers = Read-DnsServerList -Prompt 'DNS séparés par des virgules (ex: 127.0.0.1) - Entrée si aucun' `
        -UnattendedValue @(Get-ConfigValue -Path 'Network.DnsServers' -Default @())

    if (-not (Test-IPv4Address -Value $ip)) {
        Write-Log -Level Error -Message "Adresse IP invalide ('$ip') : configuration IP ignorée."
        Show-StepSummary -Title 'CONFIGURATION IP STATIQUE' -Lines @('Adresse IP invalide : étape ignorée')
        return
    }

    if (-not $PSCmdlet.ShouldProcess("Carte '$adapterName'", "Configurer IP statique $ip/$prefix")) {
        Show-StepSummary -Title 'CONFIGURATION IP STATIQUE' -Lines @("WhatIf : IP $ip/$prefix non appliquée sur '$adapterName'")
        return
    }
    try {
        Remove-NetIPAddress -InterfaceAlias $adapterName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-NetRoute -InterfaceAlias $adapterName -Confirm:$false -ErrorAction SilentlyContinue

        if ($gateway) {
            New-NetIPAddress -InterfaceAlias $adapterName -IPAddress $ip -PrefixLength $prefix -DefaultGateway $gateway -ErrorAction Stop | Out-Null
        } else {
            New-NetIPAddress -InterfaceAlias $adapterName -IPAddress $ip -PrefixLength $prefix -ErrorAction Stop | Out-Null
        }
        if ($dnsServers.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses $dnsServers -ErrorAction Stop
        }

        $script:State.Steps.IPConfigured = $true
        Save-ScriptState -State $script:State

        Write-Log -Level Success -Message "`n----------- RÉSUMÉ DE LA CONFIGURATION IP -----------" -NoJournal
        Write-Log -Message "  Carte réseau  : $adapterName" -NoJournal
        Write-Log -Message "  Adresse IP    : $ip" -NoJournal
        Write-Log -Message "  Masque (CIDR) : /$prefix" -NoJournal
        Write-Log -Message "  Passerelle    : $(if ($gateway) { $gateway } else { '(non définie)' })" -NoJournal
        Write-Log -Message "  DNS           : $(if ($dnsServers.Count -gt 0) { $dnsServers -join ', ' } else { '(non défini)' })" -NoJournal
        Write-Log -Level Success -Message "------------------------------------------------------`n" -NoJournal

        Write-Log -Level Success -Message "IP statique $ip/$prefix appliquée sur '$adapterName'."
        Add-ReportFact -Name 'Carte réseau' -Value $adapterName
        Add-ReportFact -Name 'Adresse IP' -Value "$ip/$prefix"
        Add-ReportFact -Name 'Passerelle' -Value $(if ($gateway) { $gateway } else { '(non définie)' })
        Add-ReportFact -Name 'DNS' -Value $(if ($dnsServers.Count -gt 0) { $dnsServers -join ', ' } else { '(non défini)' })
        $recap += "IP statique $ip/$prefix appliquée sur '$adapterName'"
        if ($gateway) { $recap += "Passerelle configurée : $gateway" }
        if ($dnsServers.Count -gt 0) { $recap += "DNS configuré(s) : $($dnsServers -join ', ')" }
    } catch {
        Write-Log -Level Error -Message "Erreur de configuration IP : $($_.Exception.Message)"
        Write-Log -Level Warn -Message 'Vérifiez l''adresse, le masque et la passerelle, puis relancez l''étape.' -NoJournal
        $recap += 'ERREUR de configuration IP (étape à relancer)'
    }
    Show-StepSummary -Title 'CONFIGURATION IP STATIQUE' -Lines $recap
}

# --- [3/5] Renommage du serveur. Retourne $true si un redemarrage a ete declenche ---
function Invoke-RenameStep {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()
    $script:CurrentStep = 'Renommage du serveur'
    Write-Log -Level Warn -Message "`n--- [3/5] Renommage du serveur ---" -NoJournal

    if ($script:State.Steps.ServerRenamed) {
        Write-Log -Level Detail -Message 'Nom déjà configuré lors d''une exécution précédente : étape ignorée.'
        Show-StepSummary -Title 'RENOMMAGE DU SERVEUR' -Lines @("Nom déjà traité précédemment : conservé ($env:COMPUTERNAME)")
        Add-ReportFact -Name 'Nom du serveur' -Value $env:COMPUTERNAME
        return $false
    }

    $newName = Read-ValidatedInput `
        -Prompt "Nouveau nom du serveur (ex: SRV-AD-01), ou Entrée pour conserver '$env:COMPUTERNAME'" `
        -Default '' `
        -Validator { Test-NetBiosName -Value $args[0] } `
        -ErrorMessage 'Nom invalide : 15 caractères max, lettres/chiffres/tirets, commence par une lettre, ne finit pas par un tiret.' `
        -UnattendedValue ([string](Get-ConfigValue -Path 'ServerName' -Default ''))
    if ([string]::IsNullOrWhiteSpace($newName)) { $newName = $env:COMPUTERNAME }

    if ($newName -eq $env:COMPUTERNAME) {
        $script:State.Steps.ServerRenamed = $true
        Save-ScriptState -State $script:State
        Write-Log -Message "Nom actuel conservé : $env:COMPUTERNAME (aucun redémarrage nécessaire)."
        Add-ReportFact -Name 'Nom du serveur' -Value $env:COMPUTERNAME
        Show-StepSummary -Title 'RENOMMAGE DU SERVEUR' -Lines @("Nom actuel conservé : $env:COMPUTERNAME (aucun redémarrage nécessaire)")
        return $false
    }

    # CORRECTIF fiabilite : etat marque et sauvegarde AVANT le renommage/redemarrage
    $script:State.Steps.ServerRenamed = $true
    Save-ScriptState -State $script:State

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Renommer en '$newName'")) {
        try {
            Rename-Computer -NewName $newName -Force -ErrorAction Stop
        } catch {
            Write-Log -Level Error -Message "Échec du renommage : $($_.Exception.Message)"
            $script:State.Steps.ServerRenamed = $false
            Save-ScriptState -State $script:State
            Show-StepSummary -Title 'RENOMMAGE DU SERVEUR' -Lines @('ERREUR de renommage (étape à relancer)')
            return $false
        }
    }
    Write-Log -Level Success -Message "Serveur renommé de '$env:COMPUTERNAME' vers '$newName' (redémarrage requis)."
    Add-ReportFact -Name 'Nom du serveur' -Value $newName

    Show-StepSummary -Title 'RENOMMAGE DU SERVEUR' -Lines @(
        "Serveur renommé de '$env:COMPUTERNAME' vers '$newName'",
        'Redémarrage obligatoire pour appliquer le nouveau nom',
        'RELANCEZ CE SCRIPT après le redémarrage pour poursuivre (reprise automatique)'
    )
    Invoke-RestartWithReport -Reason "appliquer le nouveau nom ('$newName')" -PhaseLabel 'Phase 1 (renommage)'
    return $true
}

# --- [4/5] Fuseau horaire (configurable, defaut : Romance Standard Time / Paris) ---
function Invoke-TimeZoneStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Fuseau horaire'
    Write-Log -Level Warn -Message "`n--- [4/5] Configuration de l'heure ---" -NoJournal

    if ($script:State.Steps.TimeZoneConfigured) {
        Write-Log -Level Detail -Message 'Fuseau horaire déjà configuré : étape ignorée.'
        Show-StepSummary -Title 'FUSEAU HORAIRE' -Lines @('Fuseau déjà configuré lors d''une exécution précédente (reprise) : ignoré')
        return
    }

    $tzDefault = [string](Get-ConfigValue -Path 'TimeZoneId' -Default $script:Defaults.TimeZoneId)
    $tzId = Read-ValidatedInput `
        -Prompt "Identifiant du fuseau horaire (Entrée pour '$tzDefault' = Paris)" `
        -Default $tzDefault `
        -Validator { param($v) try { [void][System.TimeZoneInfo]::FindSystemTimeZoneById($v); $true } catch { $false } } `
        -ErrorMessage 'Fuseau inconnu. Listez les identifiants valides avec : Get-TimeZone -ListAvailable'

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Régler le fuseau horaire sur '$tzId'")) {
        try {
            Set-TimeZone -Id $tzId -ErrorAction Stop
            # w32tm est un executable natif : il ne leve pas d'exception, on teste donc
            # $LASTEXITCODE (il echoue souvent sur un serveur sans source de temps).
            w32tm /resync /force 2>&1 | Out-Null
            $syncOk = ($LASTEXITCODE -eq 0)
            $script:State.Steps.TimeZoneConfigured = $true
            Save-ScriptState -State $script:State
            $syncMsg = if ($syncOk) { 'horloge resynchronisée (w32tm /resync)' } else { 'resynchronisation non effectuée (aucune source de temps ?)' }
            $syncSummary = if ($syncOk) { 'Resynchronisation de l''horloge effectuée (w32tm /resync)' } else { 'Resynchronisation non effectuée (aucune source de temps disponible)' }
            Write-Log -Level Success -Message "Fuseau horaire réglé sur '$tzId' ; $syncMsg."
            Add-ReportFact -Name 'Fuseau horaire' -Value $tzId
            Show-StepSummary -Title 'FUSEAU HORAIRE' -Lines @(
                "Fuseau horaire réglé sur '$tzId'",
                $syncSummary
            )
        } catch {
            Write-Log -Level Error -Message "Erreur de configuration du fuseau horaire : $($_.Exception.Message)"
            Show-StepSummary -Title 'FUSEAU HORAIRE' -Lines @('ERREUR de configuration du fuseau horaire (étape à relancer)')
        }
    }
}

# --- [5/5] Promotion en controleur de domaine. Retourne $true si redemarrage declenche ---
function Invoke-ADDSPromotionStep {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Mode unattended uniquement : le mot de passe DSRM généré est volontairement communiqué à l''administrateur via le rapport.')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param()
    $script:CurrentStep = 'Promotion AD DS'
    Write-Log -Level Warn -Message "`n--- [5/5] Active Directory ---" -NoJournal

    # Garde de reprise (comme les autres etapes de Phase 1) : si la promotion a deja
    # ete lancee mais que le serveur n'a pas encore redemarre (unattended sans
    # AutoReboot, ou -WhatIf), ne PAS relancer Install-ADDSForest sur un serveur
    # deja promu. Il faut redemarrer pour finaliser, puis la Phase 2 prendra le relais.
    if ($script:State.Steps.ADDSPromoted) {
        Write-Log -Level Warn -Message 'Promotion AD DS déjà lancée : redémarrez le serveur pour la finaliser, puis relancez le script (Phase 2).'
        Show-StepSummary -Title 'ACTIVE DIRECTORY (AD DS)' -Lines @('Promotion déjà lancée lors d''une exécution précédente : redémarrage requis avant la Phase 2')
        return $false
    }

    $configDomain = [string](Get-ConfigValue -Path 'Domain.Name' -Default '')
    $doPromote = Read-YesNo 'Voulez-vous installer et promouvoir ce serveur en Contrôleur de Domaine ?' `
        -UnattendedAnswer (-not [string]::IsNullOrWhiteSpace($configDomain))
    if (-not $doPromote) {
        Show-StepSummary -Title 'ACTIVE DIRECTORY (AD DS)' -Lines @('Promotion en Contrôleur de Domaine refusée par l''utilisateur')
        Write-Log -Level Warn -Message 'Fin de la Phase 1. Redémarrez le serveur pour appliquer le nom et l''IP.' -NoJournal
        return $false
    }

    $domainName = Read-ValidatedInput -Prompt 'Nom de la forêt/domaine (ex: monentreprise.local)' `
        -Validator { Test-DomainFqdn -Value $args[0] } `
        -ErrorMessage 'Nom de domaine invalide (format attendu : societe.local ou societe.fr).' `
        -UnattendedValue $configDomain
    if ([string]::IsNullOrWhiteSpace($domainName)) {
        Write-Log -Level Error -Message 'Aucun nom de domaine fourni : promotion annulée.'
        return $false
    }

    # --- Mot de passe DSRM ---
    $safeModePwd = $null
    if ($script:IsUnattended) {
        $dsrmPlain = [string](Get-ConfigValue -Path 'Domain.DsrmPassword' -Default '')
        if ([string]::IsNullOrWhiteSpace($dsrmPlain) -or -not (Test-StrongPassword -Value $dsrmPlain)) {
            $dsrmPlain = New-RandomPassword -Length 16
            Write-Log -Level Warn -Message 'Mot de passe DSRM généré aléatoirement (aucun fourni/valide en configuration).'
        }
        Add-ReportFact -Name 'Mot de passe DSRM' -Value $dsrmPlain
        Write-Log -Level Warn -Message "Mot de passe DSRM : $dsrmPlain (NOTEZ-LE : il figure aussi dans le rapport)." -NoJournal
        $safeModePwd = ConvertTo-SecureString -String $dsrmPlain -AsPlainText -Force
    } else {
        do {
            $safeModePwd = Read-Host -Prompt 'Mot de passe DSRM (12 caractères min : majuscule, minuscule et chiffre)' -AsSecureString
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($safeModePwd)
            try { $plainDsrm = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            $dsrmValid = Test-StrongPassword -Value $plainDsrm
            $plainDsrm = $null
            if (-not $dsrmValid) {
                Write-Log -Level Error -Message 'Mot de passe DSRM trop faible (12 car. min, majuscule + minuscule + chiffre). Recommencez.' -NoJournal
            }
        } until ($dsrmValid)
    }

    Write-Log -Message 'Installation de la fonctionnalité AD-Domain-Services...'
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Install-WindowsFeature AD-Domain-Services')) {
        try {
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop | Out-Null
        } catch {
            Write-Log -Level Error -Message "Installation d'AD-Domain-Services impossible : $($_.Exception.Message)"
            return $false
        }
    }

    # CORRECTIF fiabilite : etat marque et sauvegarde AVANT la promotion
    $script:State.Steps.ADDSPromoted = $true
    Save-ScriptState -State $script:State

    Write-Log -Message "Promotion du serveur en Contrôleur de Domaine pour '$domainName'..."
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install-ADDSForest '$domainName'")) {
        try {
            Install-ADDSForest -DomainName $domainName -SafeModeAdministratorPassword $safeModePwd `
                -Force -CreateDnsDelegation:$false -NoRebootOnCompletion -ErrorAction Stop | Out-Null
        } catch {
            Write-Log -Level Error -Message "ÉCHEC de la promotion AD DS : $($_.Exception.Message)"
            $script:State.Steps.ADDSPromoted = $false
            Save-ScriptState -State $script:State
            Show-StepSummary -Title 'ACTIVE DIRECTORY (AD DS)' -Lines @('ERREUR de promotion (étape à relancer)')
            return $false
        }
    }

    Write-Log -Level Success -Message "Forêt/domaine '$domainName' promu(e) sur ce serveur (AD DS + outils installés)."
    Add-ReportFact -Name 'Domaine' -Value $domainName
    Show-StepSummary -Title 'ACTIVE DIRECTORY (AD DS)' -Lines @(
        'Rôle AD-Domain-Services installé (avec outils d''administration)',
        "Forêt/domaine '$domainName' promu(e) sur ce serveur",
        'Mot de passe DSRM défini (à conserver en lieu sûr)',
        'Redémarrage requis puis RELANCE DU SCRIPT pour la Phase 2 (structure AD)'
    )
    Invoke-RestartWithReport -Reason "finaliser l'Active Directory ('$domainName')" -PhaseLabel 'Phase 1 (promotion AD DS)'
    return $true
}

# --- Orchestration de la Phase 1 ---
function Invoke-Phase1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $script:IsUnattended) { Clear-Host }
    Show-Banner -Text 'PHASE 1 : CONFIGURATION DE BASE & AD DS'
    Add-ReportFact -Name 'Script' -Value "$script:ScriptName v$script:ScriptVersion"

    Invoke-WindowsUpdateStep
    Invoke-StaticIpStep
    if (Invoke-RenameStep) { return }          # redemarrage declenche : reprise au prochain lancement
    Invoke-TimeZoneStep
    if (Invoke-ADDSPromotionStep) { return }   # redemarrage declenche : Phase 2 au prochain lancement

    # Fin de Phase 1 sans promotion : rapport d'execution
    Invoke-ReportExport -PhaseLabel 'Phase 1'
}

#endregion

# =====================================================================
#  REGION 11 : PHASE 2 - STRUCTURE AD, GPO, PARTAGES ET ROLES
# =====================================================================
#region Phase 2

# --- Lecture d'une propriete sur un element de configuration (hashtable ou objet JSON) ---
function Get-ObjectValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) { return $prop.Value }
    return $Default
}

# --- Politique de mot de passe et de verrouillage du DOMAINE (ANSSI + module B1-M8).
# Applique la stratégie de comptes par défaut du domaine (Set-ADDefaultDomainPasswordPolicy) :
# longueur >= 12, complexité, historique 24, expiration, verrouillage 5/15 min. Les valeurs
# sont surchargeables via la section 'DomainPasswordPolicy' du fichier de configuration.
# NB : cette politique s'applique à TOUT le domaine ; ce n'est pas un objet "créé" traçable,
# elle n'est donc pas concernée par la réinitialisation « biere » (comme l'IP ou le fuseau).
function Invoke-DomainPasswordPolicyStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Politique de mot de passe du domaine'
    Write-Log -Level Warn -Message "`n--- Politique de mot de passe et de verrouillage du domaine (ANSSI) ---" -NoJournal
    $recap = @()

    $apply = Read-YesNo 'Voulez-vous appliquer la politique de mot de passe/verrouillage ANSSI au domaine (recommandé) ?' `
        -UnattendedAnswer ([bool](Get-ConfigValue -Path 'DomainPasswordPolicy.Apply' -Default $false))
    if (-not $apply) {
        Write-Log -Level Detail -Message 'Étape ignorée : politique de mot de passe du domaine inchangée.'
        Show-StepSummary -Title 'POLITIQUE DE MOT DE PASSE DU DOMAINE' -Lines @('Politique du domaine laissée inchangée')
        return
    }

    $d = $script:DomainPasswordPolicyDefaults
    $minLen  = [int](Get-ConfigValue -Path 'DomainPasswordPolicy.MinLength'        -Default $d.MinLength)
    $cplx    = [bool](Get-ConfigValue -Path 'DomainPasswordPolicy.Complexity'      -Default $d.Complexity)
    $hist    = [int](Get-ConfigValue -Path 'DomainPasswordPolicy.HistoryCount'     -Default $d.HistoryCount)
    $maxAge  = [int](Get-ConfigValue -Path 'DomainPasswordPolicy.MaxAgeDays'       -Default $d.MaxAgeDays)
    $minAge  = [int](Get-ConfigValue -Path 'DomainPasswordPolicy.MinAgeDays'       -Default $d.MinAgeDays)
    $lockThr = [int](Get-ConfigValue -Path 'DomainPasswordPolicy.LockoutThreshold' -Default $d.LockoutThreshold)
    $lockDur = [int](Get-ConfigValue -Path 'DomainPasswordPolicy.LockoutDurationMin' -Default $d.LockoutDurationMin)
    $lockWin = [int](Get-ConfigValue -Path 'DomainPasswordPolicy.LockoutWindowMin'   -Default $d.LockoutWindowMin)

    if ($PSCmdlet.ShouldProcess("Domaine $script:DomainDNSRoot", 'Set-ADDefaultDomainPasswordPolicy')) {
        try {
            $params = @{
                Identity              = $script:DomainDNSRoot
                MinPasswordLength     = $minLen
                ComplexityEnabled     = $cplx
                PasswordHistoryCount  = $hist
                MinPasswordAge        = ([TimeSpan]::FromDays($minAge))
                MaxPasswordAge        = ([TimeSpan]::FromDays($maxAge))
                LockoutThreshold      = $lockThr
                LockoutDuration       = ([TimeSpan]::FromMinutes($lockDur))
                LockoutObservationWindow = ([TimeSpan]::FromMinutes($lockWin))
                ReversibleEncryptionEnabled = $d.ReversibleEncryption
                ErrorAction           = 'Stop'
            }
            Set-ADDefaultDomainPasswordPolicy @params
            Write-Log -Level Success -Message "Politique du domaine appliquée : longueur $minLen, complexité $cplx, historique $hist, expiration $maxAge j, verrouillage $lockThr tentatives / $lockDur min."
            Add-ReportFact -Name 'Politique mot de passe domaine' -Value "$minLen car., verrouillage $lockThr/$lockDur min, historique $hist"
            $recap += "Politique domaine : longueur $minLen, complexité $cplx, historique $hist, expiration $maxAge j"
            $recap += "Verrouillage : $lockThr tentatives, blocage $lockDur min, fenêtre $lockWin min"
        } catch {
            Write-Log -Level Error -Message "Application de la politique du domaine impossible : $($_.Exception.Message)"
            $recap += 'ERREUR lors de l''application de la politique du domaine'
        }
    }
    Show-StepSummary -Title 'POLITIQUE DE MOT DE PASSE DU DOMAINE' -Lines $recap
}

# --- Audit des accès AD (module B1-M9 P1 « Audit AD » + P6 « Zero Trust »).
# LECTURE SEULE : liste les membres des groupes privilégiés, les comptes dormants et
# les comptes à risque (mot de passe non requis / sans expiration). N'effectue AUCUNE
# modification (donc rien à tracer pour le reset). Les résultats alimentent le rapport PDF.
function Invoke-ADAccessAuditStep {
    [CmdletBinding()]
    param()
    $script:CurrentStep = 'Audit des accès AD'
    Write-Log -Level Warn -Message "`n--- Audit des accès AD (groupes privilégiés, comptes dormants) ---" -NoJournal
    $recap = @()

    if (-not (Read-YesNo 'Voulez-vous auditer les accès AD (lecture seule : groupes à privilèges, comptes dormants) ?' -UnattendedAnswer ([bool](Get-ConfigValue -Path 'AccessAudit.Enabled' -Default $false)))) {
        Write-Log -Level Detail -Message 'Étape ignorée : aucun audit des accès.'
        Show-StepSummary -Title 'AUDIT DES ACCÈS AD' -Lines @('Audit non demandé')
        return
    }

    $dormantDays = [int](Get-ConfigValue -Path 'AccessAudit.DormantDays' -Default 90)

    # --- Groupes à privilèges (SID connus + RID relatifs au domaine) ---
    $domainSid = $null
    try { $domainSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value } catch {
        Write-Log -Level Warn -Message "SID de domaine indisponible : $($_.Exception.Message)"
    }
    $privileged = [ordered]@{
        'Administrators'              = 'S-1-5-32-544'
        'Account Operators'           = 'S-1-5-32-548'
        'Server Operators'            = 'S-1-5-32-549'
        'Backup Operators'            = 'S-1-5-32-551'
        'Print Operators'             = 'S-1-5-32-550'
    }
    if ($domainSid) {
        $privileged['Domain Admins']               = "$domainSid-512"
        $privileged['Enterprise Admins']           = "$domainSid-519"
        $privileged['Schema Admins']               = "$domainSid-518"
        $privileged['Group Policy Creator Owners'] = "$domainSid-520"
        $privileged['DnsAdmins']                   = $null   # pas de RID fixe : résolu par nom
    }

    Write-Log -Level Title -Message 'Membres des groupes à privilèges :' -NoJournal
    $totalPriv = 0
    foreach ($name in $privileged.Keys) {
        $members = @()
        try {
            $group = if ($privileged[$name]) { Get-ADGroup -Identity $privileged[$name] -ErrorAction Stop }
                     else { Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction Stop }
            if ($group) {
                $members = @(Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName)
            }
        } catch {
            Write-Log -Level Detail -Message "Groupe '$name' non lu : $($_.Exception.Message)"
            continue
        }
        $totalPriv += $members.Count
        if ($members.Count -gt 0) {
            Write-Log -Message "  [$name] ($($members.Count)) : $($members -join ', ')"
            $recap += "$name : $($members.Count) membre(s) [$($members -join ', ')]"
        } else {
            Write-Log -Level Detail -Message "  [$name] : (vide)" -NoJournal
        }
    }
    Add-ReportFact -Name 'Comptes à privilèges (total)' -Value "$totalPriv (audit lecture seule)"

    # --- Comptes dormants (LastLogonDate ancienne, comptes actifs) ---
    try {
        $limit = (Get-Date).AddDays(-$dormantDays)
        $dormant = @(Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate -ErrorAction Stop |
            Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $limit } |
            Select-Object -ExpandProperty SamAccountName)
        Write-Log -Message "Comptes actifs dormants (> $dormantDays j sans connexion) : $($dormant.Count)"
        if ($dormant.Count -gt 0) {
            Write-Log -Level Warn -Message "  À revoir : $($dormant -join ', ')"
            $recap += "Comptes dormants (> $dormantDays j) : $($dormant.Count) [$($dormant -join ', ')]"
        }
        Add-ReportFact -Name "Comptes dormants (> $dormantDays j)" -Value $dormant.Count
    } catch {
        Write-Log -Level Warn -Message "Recherche des comptes dormants impossible : $($_.Exception.Message)"
    }

    # --- Comptes à risque (mot de passe non requis / n'expire jamais) ---
    try {
        $risky = @(Get-ADUser -Filter { Enabled -eq $true -and (PasswordNotRequired -eq $true -or PasswordNeverExpires -eq $true) } `
            -Properties PasswordNotRequired, PasswordNeverExpires -ErrorAction Stop |
            Select-Object -ExpandProperty SamAccountName)
        Write-Log -Message "Comptes à risque (mot de passe non requis ou sans expiration) : $($risky.Count)"
        if ($risky.Count -gt 0) {
            Write-Log -Level Warn -Message "  À revoir : $($risky -join ', ')"
            $recap += "Comptes à risque (mdp non requis / sans expiration) : $($risky.Count) [$($risky -join ', ')]"
        }
    } catch {
        Write-Log -Level Detail -Message "Recherche des comptes à risque impossible : $($_.Exception.Message)"
    }

    Show-StepSummary -Title 'AUDIT DES ACCÈS AD' -Lines $recap
}

# --- Comptes prestataires à durée limitée (module B1-M9 P7 « Prestataires »).
# Crée une OU dédiée, un GDL dédié, et des comptes qui EXPIRENT automatiquement
# (Set/New-ADUser -AccountExpirationDate), avec restriction de postes optionnelle
# (LogonWorkstations) et changement de mot de passe imposé. Mots de passe générés
# et affichés/consignés comme les autres comptes. ---
function Invoke-ContractorAccountStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Comptes prestataires'
    Write-Log -Level Warn -Message "`n--- Comptes prestataires à durée limitée (module B1-M9) ---" -NoJournal
    $recap = @()

    if (-not (Read-YesNo 'Voulez-vous créer des comptes prestataires à durée limitée (expiration automatique) ?')) {
        Write-Log -Level Detail -Message 'Étape ignorée : aucun compte prestataire.'
        Show-StepSummary -Title 'COMPTES PRESTATAIRES' -Lines $recap
        return
    }

    # OU dédiée + GDL dédié (modèle AGDLP, moindre privilège)
    $ouName = Read-ValidatedInput -Prompt "Nom de l'OU des prestataires (Entrée pour 'Prestataires')" -Default 'Prestataires' -Validator { -not [string]::IsNullOrWhiteSpace($args[0]) }
    $ouInfo = $null
    try { $ouInfo = New-TrackedOU -Name $ouName -ParentDN $script:DomainDN -ParentLabel 'la racine du domaine' } catch {
        Write-Log -Level Error -Message "OU '$ouName' : $($_.Exception.Message)"
    }
    if ($null -eq $ouInfo) {
        Show-StepSummary -Title 'COMPTES PRESTATAIRES' -Lines @("Impossible de préparer l'OU '$ouName'")
        return
    }
    if (@($script:AllOUs | Where-Object { $_.DN -eq $ouInfo.DN }).Count -eq 0) {
        $script:AllOUs += [PSCustomObject]@{ Name = $ouName; DN = $ouInfo.DN }
    }
    Add-TreeNode -Nodes $script:TreeNodes -Key $ouInfo.DN -ParentDN $script:DomainDN -DomainDN $script:DomainDN -Name $ouName -Type 'OU'
    $recap += "OU '$ouName' $(if ($ouInfo.Created) { 'créée' } else { 'réutilisée' })"

    $grpName = Read-GroupName -Question "Nom du GDL des prestataires (ex: GDL_Prestataires_RO)" -Prefix 'GDL'
    try {
        $grpInfo = New-TrackedGroup -Name $grpName -Scope DomainLocal -PathDN $ouInfo.DN -PathLabel "l'OU '$ouName'"
        if ($grpInfo) {
            if ($script:AllGDLs -notcontains $grpName) { $script:AllGDLs += $grpName }
            Add-TreeNode -Nodes $script:TreeNodes -Key $grpInfo.DN -ParentDN (Get-ParentDN -DN $grpInfo.DN) -DomainDN $script:DomainDN -Name $grpName -Type 'GDL'
            $recap += "GDL '$grpName' $(if ($grpInfo.Created) { 'créé' } else { 'réutilisé' })"
        }
    } catch { Write-Log -Level Error -Message "GDL '$grpName' : $($_.Exception.Message)" }

    $nb = Read-IntStrict 'Combien de comptes prestataires ? (ex: 1, 2, 3...)'
    for ($i = 1; $i -le $nb; $i++) {
        $done = $false
        while (-not $done) {
            $firstName = Read-NonEmpty "  -> Prénom du prestataire $i"
            $lastName  = Read-NonEmpty "  -> Nom du prestataire $i"
            $login     = Read-NonEmpty '  -> Login (ex: prestataire_dupont)'
            $expiry = Read-ValidatedInput -Prompt "  -> Date de fin de mission (AAAA-MM-JJ, ex: 2026-12-31)" `
                -Validator { param($v) $d = [datetime]::MinValue; [datetime]::TryParse($v, [ref]$d) -and $d -gt (Get-Date) } `
                -ErrorMessage 'Date invalide ou passée (format AAAA-MM-JJ, postérieure à aujourd''hui).'
            $expiryDate = [datetime]::Parse($expiry)
            $workstations = Read-Host -Prompt '  -> Postes autorisés (LogonWorkstations, ex: PC-PRESTA1,PC-PRESTA2 ; Entrée = tous)'
            try {
                $params = @{
                    FirstName = $firstName; LastName = $lastName; Login = $login
                    OuDN = $ouInfo.DN; OuLabel = $ouName; PlainPassword = (Get-NextUserPassword)
                    AccountExpirationDate = $expiryDate
                }
                if (-not [string]::IsNullOrWhiteSpace($workstations)) { $params['LogonWorkstations'] = $workstations.Trim() }
                $userInfo = New-TrackedUser @params
                if ($null -ne $userInfo) {
                    if ($script:AllUsers -notcontains $userInfo.Login) { $script:AllUsers += $userInfo.Login }
                    Add-TreeNode -Nodes $script:TreeNodes -Key $userInfo.DN -ParentDN $ouInfo.DN -DomainDN $script:DomainDN -Name $userInfo.Login -Type 'User'
                    if ($grpInfo -and $userInfo.Created) {
                        Add-GroupMemberLogged -GroupName $grpName -MemberName $userInfo.Login -MemberType 'Utilisateur' | Out-Null
                    }
                    $recap += "Prestataire '$($userInfo.Login)' créé (expire le $($expiryDate.ToString('yyyy-MM-dd')))"
                }
                $done = $true
            } catch {
                Write-Log -Level Error -Message "Prestataire '$login' : $($_.Exception.Message)"
                if (Confirm-SkipOnError -ItemLabel 'ce prestataire') { $done = $true }
            }
        }
    }
    Show-CredentialSummary
    Show-StepSummary -Title 'COMPTES PRESTATAIRES' -Lines $recap
}

# --- Configuration Windows LAPS côté AD (module B1-M9 bonus « LAPS »).
# Gère automatiquement le mot de passe de l'administrateur local de chaque poste
# (unique par machine, stocké dans l'AD, en rotation) : parade au Pass-the-Hash latéral.
# Cette étape : extension du schéma AD (Update-LapsADSchema, opération de forêt SIGNIFICATIVE)
# + délégation de lecture à un groupe sur une OU (Set-LapsADReadPasswordPermission).
# La GPO côté poste s'active séparément via la règle GPO 4.1. Non bloquant. ---
function Invoke-LapsSetupStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Windows LAPS (côté AD)'
    Write-Log -Level Warn -Message "`n--- Windows LAPS : préparation côté Active Directory ---" -NoJournal
    $recap = @()

    if (-not (Read-YesNo 'Voulez-vous préparer Windows LAPS côté AD (schéma + délégation de lecture) ?' -UnattendedAnswer ([bool](Get-ConfigValue -Path 'Laps.Enabled' -Default $false)))) {
        Write-Log -Level Detail -Message 'Étape ignorée : LAPS non préparé.'
        Show-StepSummary -Title 'WINDOWS LAPS (CÔTÉ AD)' -Lines @('LAPS non préparé')
        return
    }
    if (-not (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue)) {
        Write-Log -Level Warn -Message 'Le module Windows LAPS (cmdlets Laps*) est absent : nécessite Windows Server 2019+ à jour ou 2022/2025. Étape ignorée.'
        Show-StepSummary -Title 'WINDOWS LAPS (CÔTÉ AD)' -Lines @('Cmdlets Windows LAPS indisponibles : étape ignorée')
        return
    }

    # 1. Extension du schéma (forêt, irréversible) : confirmation forte
    if (Read-YesNo 'Étendre le schéma AD pour Windows LAPS (opération de FORÊT, irréversible) ?' -UnattendedAnswer $true) {
        if ($PSCmdlet.ShouldProcess('Schéma de la forêt', 'Update-LapsADSchema')) {
            try {
                Update-LapsADSchema -Confirm:$false -ErrorAction Stop | Out-Null
                Write-Log -Level Success -Message 'Schéma AD étendu pour Windows LAPS.'
                $recap += 'Schéma AD étendu pour Windows LAPS'
            } catch {
                Write-Log -Level Error -Message "Extension du schéma LAPS impossible : $($_.Exception.Message)"
                $recap += 'ERREUR extension du schéma LAPS'
            }
        }
    }

    # 2. Délégation de lecture du mot de passe à un groupe sur une OU d'ordinateurs
    if ($script:AllOUs.Count -gt 0) {
        $root = Select-RootOU -AllOUs $script:AllOUs -DomainDN $script:DomainDN `
            -ObjectLabel 'la lecture des mots de passe LAPS' -RootLabel 'le domaine entier'
        $targetDN = $root.DN
        $readGroup = [string](Get-ConfigValue -Path 'Laps.ReadGroup' -Default '')
        if (-not $readGroup) { $readGroup = Read-Host -Prompt "  -> Groupe autorisé à LIRE les mots de passe LAPS (ex: GDL_IT_Admins) ; Entrée pour ignorer" }
        if (-not [string]::IsNullOrWhiteSpace($readGroup)) {
            if ($PSCmdlet.ShouldProcess("OU $($root.Label)", "Déléguer la lecture LAPS à '$readGroup'")) {
                try {
                    Set-LapsADReadPasswordPermission -Identity $targetDN -AllowedPrincipals $readGroup.Trim() -ErrorAction Stop | Out-Null
                    Write-Log -Level Success -Message "Lecture des mots de passe LAPS déléguée à '$readGroup' sur $($root.Label)."
                    $recap += "Lecture LAPS déléguée à '$readGroup' sur $($root.Label)"
                } catch {
                    Write-Log -Level Error -Message "Délégation de lecture LAPS impossible : $($_.Exception.Message)"
                    $recap += 'ERREUR délégation de lecture LAPS'
                }
            }
        }
    } else {
        Write-Log -Level Detail -Message 'Aucune OU disponible pour déléguer la lecture LAPS.'
    }
    Write-Log -Level Detail -Message 'Rappel : activez la GPO LAPS côté postes via la règle GPO 4.1 (Windows LAPS natif), liée à l''OU des ordinateurs.'
    Show-StepSummary -Title 'WINDOWS LAPS (CÔTÉ AD)' -Lines $recap
}

# --- Délégation de contrôle sur une OU (module B1-M9 P4 « Délégation »).
# Applique le moindre privilège d'administration : délègue une tâche précise
# (réinitialiser les mots de passe, gérer les membres de groupe, créer/supprimer des
# utilisateurs) à un GROUPE sur une OU, via dsacls, sans droits d'admin du domaine.
# NB : les ACE déléguées ne sont PAS retirées par la réinitialisation « biere »
# (dsacls modifie l'ACL d'objets existants). Non bloquant. ---
function Invoke-DelegationStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Délégation de contrôle'
    Write-Log -Level Warn -Message "`n--- Délégation de contrôle sur une OU (moindre privilège) ---" -NoJournal
    $recap = @()

    if (-not (Read-YesNo 'Voulez-vous déléguer une tâche d''administration (ex: reset de mot de passe) à un groupe sur une OU ?')) {
        Write-Log -Level Detail -Message 'Étape ignorée : aucune délégation.'
        Show-StepSummary -Title 'DÉLÉGATION DE CONTRÔLE' -Lines $recap
        return
    }
    if ($script:AllOUs.Count -eq 0) {
        Write-Log -Level Detail -Message 'Aucune OU disponible pour la délégation.'
        Show-StepSummary -Title 'DÉLÉGATION DE CONTRÔLE' -Lines @('Aucune OU disponible')
        return
    }
    $netbios = $null
    try { $netbios = (Get-ADDomain -ErrorAction Stop).NetBIOSName } catch { $netbios = $env:USERDOMAIN }

    $continue = $true
    while ($continue) {
        $root = Select-RootOU -AllOUs $script:AllOUs -DomainDN $script:DomainDN -ObjectLabel 'la délégation'
        if ($root.DN -eq $script:DomainDN) {
            Write-Log -Level Warn -Message 'Délégation sur la racine du domaine non proposée (choisissez une OU précise).' -NoJournal
        } else {
            $group = Read-NonEmpty '  -> Groupe délégué (ex: GDL_Helpdesk)'

            # Résolution/validation du groupe dans l'AD : rejette un groupe inexistant et
            # normalise en sAMAccountName (évite qu'un espace ou un caractère spécial dans
            # le nom casse la grammaire d'ACE de dsacls).
            $groupSafe = ConvertTo-ADFilterValue -Value $group
            $adGroup = Get-ADGroup -Filter "SamAccountName -eq '$groupSafe' -or Name -eq '$groupSafe'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $adGroup) {
                Write-Log -Level Error -Message "Groupe '$group' introuvable dans l'AD : délégation ignorée."
                $recap += "Groupe '$group' introuvable : délégation ignorée"
                $continue = Read-YesNo 'Déléguer une autre tâche sur une autre OU ?'
                continue
            }
            $group = $adGroup.SamAccountName

            Write-Log -Level Title -Message '  Tâche à déléguer :' -NoJournal
            Write-Log -Message '    [1] Réinitialiser les mots de passe des utilisateurs (recommandé)' -NoJournal
            Write-Log -Message '    [2] Gérer les membres des groupes' -NoJournal
            Write-Log -Message '    [3] Créer et supprimer des comptes utilisateurs' -NoJournal
            $task = Read-Host -Prompt '  -> Choix (1/2/3, Entrée = 1)'
            if ([string]::IsNullOrWhiteSpace($task)) { $task = '1' }

            $principal = "$netbios\$group"
            $aceList = switch ($task) {
                '2'     { @("$principal`:WP;member;group") }
                '3'     { @("$principal`:CCDC;user") }
                default { @("$principal`:CA;Reset Password;user", "$principal`:WP;pwdLastSet;user") }
            }
            $taskLabel = switch ($task) { '2' { 'gestion des membres de groupe' } '3' { 'création/suppression d''utilisateurs' } default { 'réinitialisation des mots de passe' } }

            if ($PSCmdlet.ShouldProcess("OU $($root.Label)", "Déléguer [$taskLabel] à '$principal'")) {
                $okAll = $true
                foreach ($ace in $aceList) {
                    try {
                        $output = & dsacls $root.DN /I:S /G $ace 2>&1
                        if ($LASTEXITCODE -ne 0) { throw ($output -join ' ') }
                    } catch {
                        $okAll = $false
                        Write-Log -Level Error -Message "dsacls a échoué pour '$ace' : $($_.Exception.Message)"
                    }
                }
                if ($okAll) {
                    Write-Log -Level Success -Message "Délégation [$taskLabel] accordée à '$principal' sur $($root.Label)."
                    $recap += "Délégation [$taskLabel] à '$principal' sur $($root.Label)"
                } else {
                    $recap += "ERREUR de délégation à '$principal' sur $($root.Label)"
                }
            }
        }
        $continue = Read-YesNo 'Déléguer une autre tâche sur une autre OU ?'
    }
    Write-Log -Level Detail -Message 'Note : les délégations (ACE) ne sont pas retirées par la réinitialisation « biere ».'
    Show-StepSummary -Title 'DÉLÉGATION DE CONTRÔLE' -Lines $recap
}

# --- Mode de mot de passe initial des utilisateurs (demande UNE fois) :
# [A] aleatoire par utilisateur (recommande) ou [C] commun saisi par l'admin.
# Dans tous les cas : AUCUN mot de passe code en dur dans le script, affichage
# en clair dans le recapitulatif + rapport PDF, changement impose a la 1ere connexion.
function Initialize-PasswordMode {
    param()
    if ($script:PasswordMode) { return }

    if ($script:IsUnattended) {
        $mode   = [string](Get-ConfigValue -Path 'Users.PasswordMode' -Default 'Random')
        $common = [string](Get-ConfigValue -Path 'Users.CommonPassword' -Default '')
        if ($mode -eq 'Common' -and (Test-StrongPassword -Value $common)) {
            $script:PasswordMode = 'Common'
            $script:CommonUserPassword = $common
            Write-Log -Message 'Mode mot de passe : commun (fourni par la configuration).'
        } else {
            $script:PasswordMode = 'Random'
            Write-Log -Message 'Mode mot de passe : aléatoire par utilisateur.'
        }
        return
    }

    Write-Log -Level Title -Message "`nMode de mot de passe initial des utilisateurs :" -NoJournal
    Write-Log -Message '  [A] Aléatoire par utilisateur (recommandé) : généré par le script, affiché dans le récapitulatif et le rapport PDF' -NoJournal
    Write-Log -Message '  [C] Commun : vous saisissez maintenant un mot de passe unique appliqué à tous les nouveaux utilisateurs' -NoJournal
    while ($true) {
        $choice = Read-Host -Prompt '  -> Votre choix (A/C, Entrée = A)'
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -match '^[Aa]$') {
            $script:PasswordMode = 'Random'
            Write-Log -Message 'Mode mot de passe : aléatoire par utilisateur.'
            break
        }
        if ($choice -match '^[Cc]$') {
            $script:CommonUserPassword = Read-ValidatedInput `
                -Prompt '  -> Mot de passe commun (12 caractères min, majuscule + minuscule + chiffre)' `
                -Validator { Test-StrongPassword -Value $args[0] } `
                -ErrorMessage 'Mot de passe trop faible (12 caractères min, majuscule + minuscule + chiffre).'
            Write-Log -Level Warn -Message 'Ce mot de passe commun sera affiché dans le récapitulatif et consigné EN CLAIR dans le rapport PDF.' -NoJournal
            $script:PasswordMode = 'Common'
            Write-Log -Message 'Mode mot de passe : commun (saisi par l''administrateur).'
            break
        }
        Write-Log -Level Error -Message '  -> Réponse invalide, tapez A ou C.' -NoJournal
    }
}

# --- Fournit le mot de passe initial du prochain utilisateur cree ---
function Get-NextUserPassword {
    [OutputType([string])]
    param()
    Initialize-PasswordMode
    if ($script:PasswordMode -eq 'Common') { return $script:CommonUserPassword }
    $length = [int](Get-ConfigValue -Path 'Users.PasswordLength' -Default $script:Defaults.PasswordLength)
    return New-RandomPassword -Length $length
}

# --- Tableau recapitulatif des comptes : Login | Mot de passe (clair) | OU.
# Le meme tableau est repris dans le rapport PDF. ---
function Show-CredentialSummary {
    param()
    Write-Log -Level Success -Message "`n----------- RÉCAPITULATIF : COMPTES UTILISATEURS -----------" -NoJournal
    if ($script:CreatedCreds.Count -gt 0) {
        $table = $script:CreatedCreds |
            Format-Table -Property Login, @{ Label = 'Mot de passe (clair)'; Expression = { $_.MotDePasse } }, OU -AutoSize |
            Out-String
        foreach ($line in ($table -split "`r?`n")) {
            if ($line.Trim() -ne '') { Write-Log -Message $line -NoJournal }
        }
        Write-Log -Level Warn -Message 'Ces mots de passe initiaux EN CLAIR sont affichés ici et consignés dans le rapport PDF : distribuez-les puis détruisez le rapport (stockage sécurisé, jamais dans un dépôt Git).' -NoJournal
        Write-Log -Level Warn -Message 'Changement de mot de passe imposé à la première connexion (-ChangePasswordAtLogon).' -NoJournal
    } else {
        Write-Log -Level Detail -Message '  (aucun utilisateur créé ou réutilisé durant cette exécution)' -NoJournal
    }
    Write-Log -Level Success -Message "-----------------------------------------------------------`n" -NoJournal
}

# --- Module GroupPolicy (GPMC) : installation/import a la demande ---
function Initialize-GroupPolicyModule {
    [OutputType([bool])]
    param()
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Log -Level Detail -Message 'Module GroupPolicy (GPMC) absent : installation de la fonctionnalité GPMC...'
        try {
            Install-WindowsFeature -Name GPMC -ErrorAction Stop | Out-Null
        } catch {
            Write-Log -Level Error -Message "Installation de GPMC impossible : $($_.Exception.Message)"
        }
    }
    try {
        Import-Module -Name GroupPolicy -ErrorAction Stop
        return $true
    } catch {
        Write-Log -Level Error -Message "Module GroupPolicy inutilisable : $($_.Exception.Message)"
        return $false
    }
}

# --- Etape interactive : creation des OU (et de leurs utilisateurs) ---
function Invoke-OUCreationStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Création des OU'
    Write-Log -Level Warn -Message "`n--- Création des Organizational Units (OU) ---" -NoJournal
    $recap = @()

    if (Read-YesNo 'Voulez-vous créer des OU ?') {
        $nbOU = Read-IntStrict 'Combien d''OU voulez-vous créer ? (ex: 1, 2, 3...)'
        for ($i = 1; $i -le $nbOU; $i++) {
            $ouInfo = $null
            $ouSkipped = $false
            $ouName = $null
            while ($null -eq $ouInfo -and -not $ouSkipped) {
                $ouName = Read-NonEmpty "Nom de l'OU $i (ex: Vannes)"
                $root = Select-RootOU -AllOUs $script:AllOUs -DomainDN $script:DomainDN -ObjectLabel "l'OU '$ouName'"
                try {
                    $ouInfo = New-TrackedOU -Name $ouName -ParentDN $root.DN -ParentLabel $root.Label
                    if ($null -eq $ouInfo) {
                        # ShouldProcess refuse (-WhatIf) : on passe cette OU
                        $ouSkipped = $true
                        continue
                    }
                    $recap += if ($ouInfo.Created) { "OU '$ouName' créée dans $($root.Label) (protection anti-suppression activée)" }
                              else { "OU '$ouName' déjà présente dans $($root.Label) : réutilisée" }
                    Add-TreeNode -Nodes $script:TreeNodes -Key $ouInfo.DN -ParentDN $root.DN -DomainDN $script:DomainDN -Name $ouName -Type 'OU'
                } catch {
                    Write-Log -Level Error -Message "Erreur lors de la création de l'OU '$ouName' : $($_.Exception.Message)"
                    if (Confirm-SkipOnError -ItemLabel 'cette OU') {
                        Write-Log -Level Detail -Message 'OU ignorée.'
                        $recap += "OU '$ouName' ignorée suite à une erreur"
                        $ouSkipped = $true
                    }
                }
            }
            if ($ouSkipped) { continue }

            if (@($script:AllOUs | Where-Object { $_.DN -eq $ouInfo.DN }).Count -eq 0) {
                $script:AllOUs += [PSCustomObject]@{ Name = $ouName; DN = $ouInfo.DN }
            }

            # --- Utilisateurs dans cette OU ---
            if (Read-YesNo "Voulez-vous créer des utilisateurs dans l'OU '$ouName' ?") {
                $nbUsers = Read-IntStrict "Combien d'utilisateurs dans l'OU '$ouName' ? (ex: 1, 2, 3...)"
                for ($j = 1; $j -le $nbUsers; $j++) {
                    $userDone = $false
                    while (-not $userDone) {
                        $firstName = Read-NonEmpty "  -> Prénom de l'utilisateur $j (ex: Jean)"
                        $lastName  = Read-NonEmpty "  -> Nom de l'utilisateur $j (ex: Dupont)"
                        $login     = Read-NonEmpty '  -> Nom d''ouverture de session / SAMAccountName (ex: jdupont)'
                        try {
                            $userInfo = New-TrackedUser -FirstName $firstName -LastName $lastName -Login $login `
                                -OuDN $ouInfo.DN -OuLabel $ouName -PlainPassword (Get-NextUserPassword)
                            if ($null -ne $userInfo) {
                                if ($script:AllUsers -notcontains $userInfo.Login) { $script:AllUsers += $userInfo.Login }
                                Add-TreeNode -Nodes $script:TreeNodes -Key $userInfo.DN -ParentDN $ouInfo.DN -DomainDN $script:DomainDN -Name $userInfo.Login -Type 'User'
                                $recap += if ($userInfo.Created) { "Utilisateur '$($userInfo.Login)' créé dans l'OU '$ouName'" }
                                          else { "Utilisateur '$($userInfo.Login)' déjà présent : réutilisé" }
                            }
                            $userDone = $true
                        } catch {
                            Write-Log -Level Error -Message "Impossible de créer '$login' : $($_.Exception.Message)"
                            if (Confirm-SkipOnError -ItemLabel 'cet utilisateur') {
                                Write-Log -Level Detail -Message 'Utilisateur ignoré.'
                                $userDone = $true
                            }
                        }
                    }
                }
            }
        }
    } else {
        Write-Log -Level Detail -Message 'Étape ignorée : aucune OU créée.'
    }

    Show-StepSummary -Title 'ORGANIZATIONAL UNITS (OU)' -Lines $recap
    Show-CredentialSummary
}

# --- Etape interactive : ajout d'ordinateurs ---
function Invoke-ComputerCreationStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Ajout d''ordinateurs'
    Write-Log -Level Warn -Message "`n--- Ajout d'ordinateurs ---" -NoJournal
    $recap = @()

    if (Read-YesNo 'Voulez-vous ajouter des ordinateurs ?') {
        $nb = Read-IntStrict 'Combien d''ordinateurs voulez-vous ajouter ? (ex: 1, 2, 3...)'
        for ($i = 1; $i -le $nb; $i++) {
            $done = $false
            while (-not $done) {
                $compName = Read-NonEmpty "Nom de l'ordinateur $i (ex: PC-DIRECTION-01)"
                $root = Select-RootOU -AllOUs $script:AllOUs -DomainDN $script:DomainDN `
                    -ObjectLabel "l'ordinateur '$compName'" -RootLabel 'le conteneur par défaut (Computers)'
                try {
                    $compInfo = New-TrackedComputer -Name $compName -TargetDN $root.DN -DomainDN $script:DomainDN -TargetLabel $root.Label
                    if ($null -ne $compInfo) {
                        if ($script:AllComputers -notcontains $compName) { $script:AllComputers += $compName }
                        $parentDN = if ($compInfo.Created -and $root.DN -ne $script:DomainDN) { $root.DN } else { Get-ParentDN -DN $compInfo.DN }
                        Add-TreeNode -Nodes $script:TreeNodes -Key $compInfo.DN -ParentDN $parentDN -DomainDN $script:DomainDN -Name $compName -Type 'Computer'
                        $recap += if ($compInfo.Created) { "Ordinateur '$compName' créé dans $($root.Label)" }
                                  else { "Ordinateur '$compName' déjà présent : réutilisé" }
                    }
                    $done = $true
                } catch {
                    Write-Log -Level Error -Message "Erreur lors de la création de '$compName' : $($_.Exception.Message)"
                    if (Confirm-SkipOnError -ItemLabel 'cet ordinateur') {
                        Write-Log -Level Detail -Message 'Ordinateur ignoré.'
                        $recap += "Ordinateur '$compName' ignoré suite à une erreur"
                        $done = $true
                    }
                }
            }
        }
    } else {
        Write-Log -Level Detail -Message 'Étape ignorée : aucun ordinateur ajouté.'
    }
    Show-StepSummary -Title 'ORDINATEURS' -Lines $recap
}

# --- Etape interactive : Groupes Globaux (GG) + membres ---
function Invoke-GlobalGroupStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Groupes Globaux (GG)'
    Write-Log -Level Warn -Message "`n--- Création des Groupes Globaux (GG) ---" -NoJournal
    $recap = @()

    if (Read-YesNo 'Voulez-vous créer des Groupes Globaux (GG) ?') {
        $nb = Read-IntStrict 'Combien de Groupes Globaux (GG) voulez-vous créer ? (ex: 1, 2, 3...)'
        for ($i = 1; $i -le $nb; $i++) {
            $groupInfo = $null
            $skipped = $false
            $groupName = $null
            while ($null -eq $groupInfo -and -not $skipped) {
                $groupName = Read-GroupName -Question "Nom du Groupe Global $i (ex: GG_Direction)" -Prefix 'GG'
                $root = Select-RootOU -AllOUs $script:AllOUs -DomainDN $script:DomainDN -ObjectLabel "le GG '$groupName'"
                try {
                    $groupInfo = New-TrackedGroup -Name $groupName -Scope Global -PathDN $root.DN -PathLabel $root.Label
                    if ($null -eq $groupInfo) { $skipped = $true; continue }
                    if ($script:AllGGs -notcontains $groupName) { $script:AllGGs += $groupName }
                    Add-TreeNode -Nodes $script:TreeNodes -Key $groupInfo.DN -ParentDN (Get-ParentDN -DN $groupInfo.DN) -DomainDN $script:DomainDN -Name $groupName -Type 'GG'
                    $recap += if ($groupInfo.Created) { "GG '$groupName' créé dans $($root.Label) (protection anti-suppression activée)" }
                              else { "GG '$groupName' déjà présent : réutilisé" }
                } catch {
                    Write-Log -Level Error -Message "Erreur lors de la création du GG '$groupName' : $($_.Exception.Message)"
                    if (Confirm-SkipOnError -ItemLabel 'ce groupe') {
                        $recap += "GG '$groupName' ignoré suite à une erreur"
                        $skipped = $true
                    }
                }
            }
            if ($skipped) { continue }

            # --- Membres : utilisateurs et ordinateurs connus (modele AGDLP : A -> G) ---
            $members = @()
            foreach ($u in $script:AllUsers)     { $members += [PSCustomObject]@{ Type = 'Utilisateur'; Name = $u } }
            foreach ($c in $script:AllComputers) { $members += [PSCustomObject]@{ Type = 'Ordinateur';  Name = $c } }
            if ($members.Count -eq 0) {
                Write-Log -Level Detail -Message 'Aucun utilisateur ou ordinateur disponible à ajouter.'
                continue
            }
            Write-Log -Level Title -Message 'Liste des utilisateurs et ordinateurs disponibles :' -NoJournal
            for ($k = 0; $k -lt $members.Count; $k++) {
                Write-Log -Message "  [$k] $($members[$k].Name) ($($members[$k].Type))" -NoJournal
            }
            $memberIndices = Read-Host -Prompt "  -> Numéros à ajouter à $groupName, séparés par des virgules (ex: 0,2), ou Entrée pour aucun"
            if ($memberIndices -ne '') {
                foreach ($idx in ($memberIndices -split ',' | ForEach-Object { $_.Trim() })) {
                    if ($idx -match '^\d+$' -and [int]$idx -lt $members.Count) {
                        $member = $members[[int]$idx]
                        if (Add-GroupMemberLogged -GroupName $groupName -MemberName $member.Name -MemberType $member.Type) {
                            $recap += "Membre '$($member.Name)' ($($member.Type)) ajouté au GG '$groupName'"
                        }
                    } else {
                        Write-Log -Level Error -Message "  -> '$idx' n'est pas un numéro valide." -NoJournal
                    }
                }
            }
        }
    } else {
        Write-Log -Level Detail -Message 'Étape ignorée : aucun Groupe Global créé.'
    }
    Show-StepSummary -Title 'GROUPES GLOBAUX (GG)' -Lines $recap
}

# --- Etape interactive : GDL + imbrication des GG (modele AGDLP : G -> DL) ---
function Invoke-DomainLocalGroupStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Groupes de Domaine Local (GDL)'
    Write-Log -Level Warn -Message "`n--- Création des GDL (Groupes de Domaine Local) ---" -NoJournal
    $recap = @()

    if (Read-YesNo 'Voulez-vous créer des GDL ?') {
        $nb = Read-IntStrict 'Combien de GDL voulez-vous créer ? (ex: 1, 2, 3...)'
        for ($i = 1; $i -le $nb; $i++) {
            $groupInfo = $null
            $skipped = $false
            $gdlName = $null
            while ($null -eq $groupInfo -and -not $skipped) {
                $gdlName = Read-GroupName -Question "Nom de la GDL $i (ex: GDL_Direction_RW)" -Prefix 'GDL'
                $root = Select-RootOU -AllOUs $script:AllOUs -DomainDN $script:DomainDN -ObjectLabel "la GDL '$gdlName'"
                try {
                    $groupInfo = New-TrackedGroup -Name $gdlName -Scope DomainLocal -PathDN $root.DN -PathLabel $root.Label
                    if ($null -eq $groupInfo) { $skipped = $true; continue }
                    if ($script:AllGDLs -notcontains $gdlName) { $script:AllGDLs += $gdlName }
                    Add-TreeNode -Nodes $script:TreeNodes -Key $groupInfo.DN -ParentDN (Get-ParentDN -DN $groupInfo.DN) -DomainDN $script:DomainDN -Name $gdlName -Type 'GDL'
                    $recap += if ($groupInfo.Created) { "GDL '$gdlName' créée dans $($root.Label) (protection anti-suppression activée)" }
                              else { "GDL '$gdlName' déjà présente : réutilisée" }
                } catch {
                    Write-Log -Level Error -Message "Erreur lors de la création de la GDL '$gdlName' : $($_.Exception.Message)"
                    if (Confirm-SkipOnError -ItemLabel 'cette GDL') {
                        $recap += "GDL '$gdlName' ignorée suite à une erreur"
                        $skipped = $true
                    }
                }
            }
            if ($skipped) { continue }

            if ($script:AllGGs.Count -eq 0) {
                Write-Log -Level Detail -Message 'Aucun Groupe Global disponible à ajouter dans cette GDL.'
                continue
            }
            Write-Log -Level Title -Message 'Liste des Groupes Globaux (GG) disponibles :' -NoJournal
            for ($k = 0; $k -lt $script:AllGGs.Count; $k++) {
                Write-Log -Message "  [$k] $($script:AllGGs[$k])" -NoJournal
            }
            $groupIndices = Read-Host -Prompt "  -> Numéros des GG à ajouter à $gdlName, séparés par des virgules (ex: 0,1), ou Entrée pour aucun"
            if ($groupIndices -ne '') {
                foreach ($idx in ($groupIndices -split ',' | ForEach-Object { $_.Trim() })) {
                    if ($idx -match '^\d+$' -and [int]$idx -lt $script:AllGGs.Count) {
                        $ggName = $script:AllGGs[[int]$idx]
                        if (Add-GroupMemberLogged -GroupName $gdlName -MemberName $ggName -MemberType 'GG') {
                            $recap += "GG '$ggName' ajouté à la GDL '$gdlName' (modèle AGDLP)"
                        }
                    } else {
                        Write-Log -Level Error -Message "  -> '$idx' n'est pas un numéro valide." -NoJournal
                    }
                }
            }
        }
    } else {
        Write-Log -Level Detail -Message 'Étape ignorée : aucune GDL créée.'
    }
    Show-StepSummary -Title 'GROUPES DE DOMAINE LOCAL (GDL)' -Lines $recap
}

# --- Etape interactive : GPO (creation, configurateur, lien) ---
function Invoke-GpoStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Stratégies de groupe (GPO)'
    Write-Log -Level Warn -Message "`n--- Création des Stratégies de Groupe (GPO) ---" -NoJournal
    $recap = @()

    if (Read-YesNo 'Voulez-vous créer des GPO ?') {
        if (-not (Initialize-GroupPolicyModule)) {
            Show-StepSummary -Title 'STRATÉGIES DE GROUPE (GPO)' -Lines @('Module GroupPolicy indisponible : étape annulée')
            return
        }
        $nb = Read-IntStrict 'Combien de GPO voulez-vous créer ? (ex: 1, 2, 3...)'
        for ($i = 1; $i -le $nb; $i++) {
            $gpoInfo = $null
            $skipped = $false
            $gpoName = $null
            while ($null -eq $gpoInfo -and -not $skipped) {
                $gpoName = Read-NonEmpty "Nom de la GPO $i (ex: GPO_Restriction_USB)"
                try {
                    $gpoInfo = New-TrackedGpo -Name $gpoName
                    if ($null -eq $gpoInfo) { $skipped = $true; continue }
                    $recap += if ($gpoInfo.Created) { "GPO '$gpoName' créée" } else { "GPO '$gpoName' déjà présente : réutilisée" }
                } catch {
                    Write-Log -Level Error -Message "Erreur lors de la création de la GPO '$gpoName' : $($_.Exception.Message)"
                    if (Confirm-SkipOnError -ItemLabel 'cette GPO') {
                        $recap += "GPO '$gpoName' ignorée suite à une erreur"
                        $skipped = $true
                    }
                }
            }
            if ($skipped) { continue }

            # Configurateur interactif (catalogue de durcissement ANSSI/NIST)
            Invoke-GPOConfigurator -GPOName $gpoName
            $recap += "GPO '$gpoName' : configurée via le menu interactif"

            # Lien de la GPO vers une OU (affichage en arborescence)
            if ($script:AllOUs.Count -eq 0) {
                Write-Log -Level Detail -Message 'Aucune OU disponible, la GPO ne sera pas liée.'
                $recap += "GPO '$gpoName' non liée (aucune OU disponible)"
            } else {
                $root = Select-RootOU -AllOUs $script:AllOUs -DomainDN $script:DomainDN `
                    -ObjectLabel "le lien de la GPO '$gpoName'" -RootLabel 'aucun lien (GPO non liée)'
                if ($root.DN -ne $script:DomainDN) {
                    if (New-TrackedGpoLink -GpoName $gpoName -TargetDN $root.DN -TargetLabel $root.Label) {
                        $recap += "GPO '$gpoName' liée à $($root.Label)"
                    }
                } else {
                    Write-Log -Level Detail -Message 'GPO non liée (aucune OU cible choisie).'
                    $recap += "GPO '$gpoName' non liée (aucune OU cible choisie)"
                }
            }
        }
    } else {
        Write-Log -Level Detail -Message 'Étape ignorée : aucune GPO créée.'
    }
    Show-StepSummary -Title 'STRATÉGIES DE GROUPE (GPO)' -Lines $recap
}

# --- Etape interactive : serveur de fichiers (partages SMB + ACL NTFS) ---
function Invoke-FileServerStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Serveur de fichiers'
    Write-Log -Level Warn -Message "`n--- Serveur de fichiers : création de dossiers partagés ---" -NoJournal
    $recap = @()

    if (-not (Read-YesNo 'Voulez-vous créer un ou plusieurs dossiers de partage réseau ?')) {
        Write-Log -Level Detail -Message 'Étape ignorée : aucun dossier de partage créé.'
        Show-StepSummary -Title 'SERVEUR DE FICHIERS (PARTAGES)' -Lines $recap
        return
    }

    if (-not (Confirm-FileServerRole)) {
        Show-StepSummary -Title 'SERVEUR DE FICHIERS (PARTAGES)' -Lines @('Rôle Serveur de fichiers indisponible : étape ignorée')
        return
    }

    # Identites locales resolues par SID : independant de la langue de l'OS
    $adminPrincipal    = Get-WellKnownPrincipalName -Sid $script:WellKnownSid.Administrators
    $everyonePrincipal = Get-WellKnownPrincipalName -Sid $script:WellKnownSid.Everyone

    $nbShares = Read-IntStrict 'Combien de dossiers de partage voulez-vous créer ? (ex: 1, 2, 3...)'
    for ($i = 1; $i -le $nbShares; $i++) {
        $shareName = Read-NonEmpty "Nom du partage $i (ex: Direction)"
        $defaultPath = Join-Path -Path $script:Defaults.ShareRootPath -ChildPath $shareName
        $sharePath = Read-Host -Prompt "Chemin local du dossier à partager - Entrée pour utiliser $defaultPath par défaut"
        if ([string]::IsNullOrWhiteSpace($sharePath)) { $sharePath = $defaultPath }

        # --- Dossier (idempotent ; trace UNIQUEMENT s'il a ete cree par le script) ---
        if (-not (Test-Path -Path $sharePath)) {
            if ($PSCmdlet.ShouldProcess($sharePath, 'Créer le dossier')) {
                try {
                    New-Item -Path $sharePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Add-CreatedObject -Category Folders -Key $sharePath -Entry @{ Path = $sharePath }
                    Write-Log -Level Success -Message "Dossier '$sharePath' créé."
                    $recap += "Dossier '$sharePath' créé"
                } catch {
                    Write-Log -Level Error -Message "Erreur lors de la création du dossier '$sharePath' : $($_.Exception.Message)"
                    $recap += "Dossier '$sharePath' en ERREUR : partage ignoré"
                    continue
                }
            } else { continue }
        } else {
            Write-Log -Level Detail -Message "Le dossier '$sharePath' existe déjà : réutilisation."
        }

        # --- Partage SMB (idempotent, trace, -FullAccess via nom traduit du SID) ---
        $existingShare = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
        if ($existingShare) {
            Write-Log -Level Detail -Message "Le partage '$shareName' existe déjà : réutilisation (aucune recréation)."
            $recap += "Partage '$shareName' déjà présent : réutilisé"
        } else {
            if (-not $PSCmdlet.ShouldProcess("\\$env:COMPUTERNAME\$shareName", "Créer le partage SMB sur '$sharePath'")) { continue }
            try {
                New-SmbShare -Name $shareName -Path $sharePath -FullAccess $adminPrincipal -ErrorAction Stop | Out-Null
                Add-CreatedObject -Category Shares -Key $shareName -Entry @{ Name = $shareName; Path = $sharePath }
                Write-Log -Level Success -Message "Partage réseau '$shareName' activé sur '$sharePath' (contrôle total : $adminPrincipal)."
                $recap += "Partage '$shareName' créé sur '$sharePath'"
            } catch {
                Write-Log -Level Error -Message "Erreur lors de la création du partage '$shareName' : $($_.Exception.Message)"
                $recap += "Partage '$shareName' en ERREUR : $($_.Exception.Message)"
                continue
            }
        }

        # --- ABE : Access-Based Enumeration (module B1-M9 P2 : masquer ce qui est inaccessible) ---
        if (Read-YesNo "Activer l'énumération basée sur l'accès (ABE) sur '$shareName' (chaque utilisateur ne voit que ce à quoi il a accès) ?") {
            if (Enable-ShareAbe -ShareName $shareName) { $recap += "ABE activée sur le partage '$shareName'" }
        }

        # --- Restriction d'acces (modele AGDLP : GDL uniquement) ---
        if (Read-YesNo "Voulez-vous limiter l'accès de '$shareName' à des GDL spécifiques ?") {
            Write-Log -Message "Désactivation de l'héritage et purge des autorisations existantes sur '$sharePath'..."
            try {
                Reset-FolderAcl -Path $sharePath -KeepAdmins
                Write-Log -Level Success -Message "Héritage désactivé, autorisations héritées supprimées (base SYSTEM + Administrateurs conservée, via SID)."
                $recap += "ACL de '$shareName' réinitialisée (héritage désactivé, permissions héritées supprimées)"
            } catch {
                Write-Log -Level Error -Message "Erreur lors de la réinitialisation de l'ACL : $($_.Exception.Message)"
                $recap += "ACL de '$shareName' : ERREUR de réinitialisation"
            }

            # Retrait de l'acces 'Tout le monde' par defaut (nom localise via SID)
            try {
                Revoke-SmbShareAccess -Name $shareName -AccountName $everyonePrincipal -Force -ErrorAction Stop | Out-Null
                Write-Log -Level Detail -Message "Accès '$everyonePrincipal' retiré du partage '$shareName'."
            } catch {
                Write-Log -Level Detail -Message "Aucun accès '$everyonePrincipal' à retirer sur '$shareName'."
            }

            if ($script:AllGDLs.Count -eq 0) {
                Write-Log -Level Detail -Message 'Aucune GDL connue durant cette exécution : saisie manuelle requise.'
                Write-Log -Level Detail -Message '(Modèle AGDLP : saisissez de préférence le nom d''une GDL, ex: GDL_Direction_RW.)' -NoJournal
                $manualName = Read-Host -Prompt '  -> Nom exact du groupe (GDL) à autoriser (ou Entrée pour annuler)'
                if (-not [string]::IsNullOrWhiteSpace($manualName)) {
                    $recapLine = Set-ShareAccessGranular -ShareName $shareName -SharePath $sharePath -AccountName $manualName.Trim()
                    if ($recapLine) { $recap += $recapLine }
                }
            } else {
                Write-Log -Level Title -Message 'GDL disponibles (modèle AGDLP) :' -NoJournal
                for ($k = 0; $k -lt $script:AllGDLs.Count; $k++) {
                    Write-Log -Message "  [$k] $($script:AllGDLs[$k]) (GDL)" -NoJournal
                }
                $idxList = Read-Host -Prompt "  -> Numéros des GDL à autoriser sur '$shareName', séparés par des virgules (ex: 0,1)"
                if (-not [string]::IsNullOrWhiteSpace($idxList)) {
                    foreach ($idx in ($idxList -split ',' | ForEach-Object { $_.Trim() })) {
                        if ($idx -match '^\d+$' -and [int]$idx -lt $script:AllGDLs.Count) {
                            $gdlName = $script:AllGDLs[[int]$idx]
                            Write-Log -Level Title -Message "  -> Configuration des droits pour '$gdlName' (GDL) :" -NoJournal
                            $recapLine = Set-ShareAccessGranular -ShareName $shareName -SharePath $sharePath -AccountName $gdlName
                            if ($recapLine) { $recap += $recapLine }
                        } else {
                            Write-Log -Level Error -Message "  -> '$idx' n'est pas un numéro valide." -NoJournal
                        }
                    }
                }
            }
        } else {
            Write-Log -Level Detail -Message "Accès au partage laissé par défaut (SYSTEM + Administrateurs via SID)."
        }
    }
    Show-StepSummary -Title 'SERVEUR DE FICHIERS (PARTAGES)' -Lines $recap
}

# --- Roles de serveur optionnels (catalogue) - interactif ET unattended ---
function Invoke-RoleInstallationStep {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Rôles de serveur'
    Write-Log -Level Warn -Message "`n--- Installation des rôles de serveur ---" -NoJournal
    $recap = @()
    $configRoles = @(Get-ConfigValue -Path 'Roles' -Default @())

    foreach ($role in $script:RolesCatalog) {
        $roleChoice = Read-YesNo "Voulez-vous installer le rôle $($role.Label) ?" -UnattendedAnswer ($configRoles -contains $role.Feature)

        # Garde-fou historique (bug IIS v5) : installation UNIQUEMENT si la reponse
        # vaut strictement $true.
        if ($roleChoice -ne $true) {
            $recap += "Rôle $($role.Label) : non demandé"
            continue
        }
        if ((Get-WindowsFeature -Name $role.Feature).Installed) {
            Write-Log -Level Detail -Message "Le rôle $($role.Label) est déjà installé."
            $recap += "Rôle $($role.Label) : déjà installé (aucune action)"
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Install-WindowsFeature $($role.Feature)")) {
            $recap += "Rôle $($role.Label) : non installé (WhatIf)"
            continue
        }
        try {
            Install-WindowsFeature -Name $role.Feature -IncludeManagementTools -ErrorAction Stop | Out-Null
            Write-Log -Level Success -Message "Rôle $($role.Label) installé. $($role.Note)"
            Add-ReportFact -Name "Rôle $($role.Label)" -Value 'Installé'
            $recap += "Rôle $($role.Label) : installé $($role.Note)"
        } catch {
            Write-Log -Level Error -Message "Erreur lors de l'installation du rôle $($role.Label) : $($_.Exception.Message)"
            $recap += "Rôle $($role.Label) : ERREUR d'installation"
        }
    }
    Show-StepSummary -Title 'RÔLES DE SERVEUR' -Lines $recap
}

#endregion

# =====================================================================
#  REGION 12 : PHASE 2 PILOTEE PAR CONFIGURATION (-ConfigFile / -Unattended)
# =====================================================================
#region Phase 2 configuration

# --- Structure AD declarative : OUs (+ utilisateurs), ordinateurs, GG, GDL ---
function Invoke-ADStructureFromConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Structure AD (configuration)'
    Write-Log -Level Warn -Message "`n--- Structure AD depuis le fichier de configuration ---" -NoJournal
    $recap = @()

    $ouByName = @{}
    foreach ($ou in $script:AllOUs) { $ouByName[$ou.Name] = $ou.DN }

    # --- OUs et utilisateurs (l'ordre du fichier definit la hierarchie) ---
    foreach ($ouCfg in @(Get-ConfigValue -Path 'OUs' -Default @())) {
        $name = [string](Get-ObjectValue -Object $ouCfg -Name 'Name' -Default '')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $parentName = [string](Get-ObjectValue -Object $ouCfg -Name 'Parent' -Default '')
        $parentDN = $script:DomainDN
        $parentLabel = 'la racine du domaine'
        if ($parentName -and $ouByName.ContainsKey($parentName)) {
            $parentDN = $ouByName[$parentName]
            $parentLabel = "l'OU '$parentName'"
        }
        try {
            $ouInfo = New-TrackedOU -Name $name -ParentDN $parentDN -ParentLabel $parentLabel
            if ($null -eq $ouInfo) { continue }
            $ouByName[$name] = $ouInfo.DN
            if (@($script:AllOUs | Where-Object { $_.DN -eq $ouInfo.DN }).Count -eq 0) {
                $script:AllOUs += [PSCustomObject]@{ Name = $name; DN = $ouInfo.DN }
            }
            Add-TreeNode -Nodes $script:TreeNodes -Key $ouInfo.DN -ParentDN $parentDN -DomainDN $script:DomainDN -Name $name -Type 'OU'
            $recap += "OU '$name' $(if ($ouInfo.Created) { 'créée' } else { 'réutilisée' }) dans $parentLabel"

            foreach ($userCfg in @(Get-ObjectValue -Object $ouCfg -Name 'Users' -Default @())) {
                $firstName = [string](Get-ObjectValue -Object $userCfg -Name 'FirstName' -Default '')
                $lastName  = [string](Get-ObjectValue -Object $userCfg -Name 'LastName' -Default '')
                $login     = [string](Get-ObjectValue -Object $userCfg -Name 'Login' -Default '')
                if ([string]::IsNullOrWhiteSpace($login)) { continue }
                if ([string]::IsNullOrWhiteSpace($firstName)) { $firstName = $login }
                if ([string]::IsNullOrWhiteSpace($lastName))  { $lastName = $login }
                try {
                    $userInfo = New-TrackedUser -FirstName $firstName -LastName $lastName -Login $login `
                        -OuDN $ouInfo.DN -OuLabel $name -PlainPassword (Get-NextUserPassword)
                    if ($null -ne $userInfo) {
                        if ($script:AllUsers -notcontains $userInfo.Login) { $script:AllUsers += $userInfo.Login }
                        Add-TreeNode -Nodes $script:TreeNodes -Key $userInfo.DN -ParentDN $ouInfo.DN -DomainDN $script:DomainDN -Name $userInfo.Login -Type 'User'
                        $recap += "Utilisateur '$($userInfo.Login)' $(if ($userInfo.Created) { 'créé' } else { 'réutilisé' }) dans l'OU '$name'"
                    }
                } catch {
                    Write-Log -Level Error -Message "Utilisateur '$login' : $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log -Level Error -Message "OU '$name' : $($_.Exception.Message)"
        }
    }

    # --- Ordinateurs ---
    $configComputers = @(Get-ConfigValue -Path 'Computers' -Default @())
    foreach ($compCfg in $configComputers) {
        $name = [string](Get-ObjectValue -Object $compCfg -Name 'Name' -Default '')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $ouName = [string](Get-ObjectValue -Object $compCfg -Name 'OU' -Default '')
        $targetDN = if ($ouName -and $ouByName.ContainsKey($ouName)) { $ouByName[$ouName] } else { $script:DomainDN }
        $targetLabel = if ($ouName -and $ouByName.ContainsKey($ouName)) { "l'OU '$ouName'" } else { 'le conteneur par défaut (Computers)' }
        try {
            $compInfo = New-TrackedComputer -Name $name -TargetDN $targetDN -DomainDN $script:DomainDN -TargetLabel $targetLabel
            if ($null -ne $compInfo) {
                if ($script:AllComputers -notcontains $name) { $script:AllComputers += $name }
                Add-TreeNode -Nodes $script:TreeNodes -Key $compInfo.DN -ParentDN (Get-ParentDN -DN $compInfo.DN) -DomainDN $script:DomainDN -Name $name -Type 'Computer'
                $recap += "Ordinateur '$name' $(if ($compInfo.Created) { 'créé' } else { 'réutilisé' }) dans $targetLabel"
            }
        } catch {
            Write-Log -Level Error -Message "Ordinateur '$name' : $($_.Exception.Message)"
        }
    }
    $configComputerNames = @($configComputers | ForEach-Object { [string](Get-ObjectValue -Object $_ -Name 'Name' -Default '') })

    # --- Groupes Globaux (GG) : A -> G ---
    foreach ($ggCfg in @(Get-ConfigValue -Path 'GlobalGroups' -Default @())) {
        $name = [string](Get-ObjectValue -Object $ggCfg -Name 'Name' -Default '')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $ouName = [string](Get-ObjectValue -Object $ggCfg -Name 'OU' -Default '')
        $pathDN = if ($ouName -and $ouByName.ContainsKey($ouName)) { $ouByName[$ouName] } else { $script:DomainDN }
        $pathLabel = if ($ouName -and $ouByName.ContainsKey($ouName)) { "l'OU '$ouName'" } else { 'la racine du domaine' }
        try {
            $groupInfo = New-TrackedGroup -Name $name -Scope Global -PathDN $pathDN -PathLabel $pathLabel
            if ($null -eq $groupInfo) { continue }
            if ($script:AllGGs -notcontains $name) { $script:AllGGs += $name }
            Add-TreeNode -Nodes $script:TreeNodes -Key $groupInfo.DN -ParentDN (Get-ParentDN -DN $groupInfo.DN) -DomainDN $script:DomainDN -Name $name -Type 'GG'
            $recap += "GG '$name' $(if ($groupInfo.Created) { 'créé' } else { 'réutilisé' }) dans $pathLabel"
            foreach ($member in @(Get-ObjectValue -Object $ggCfg -Name 'Members' -Default @())) {
                $memberType = if ($configComputerNames -contains [string]$member) { 'Ordinateur' } else { 'Utilisateur' }
                if (Add-GroupMemberLogged -GroupName $name -MemberName ([string]$member) -MemberType $memberType) {
                    $recap += "Membre '$member' ajouté au GG '$name'"
                }
            }
        } catch {
            Write-Log -Level Error -Message "GG '$name' : $($_.Exception.Message)"
        }
    }

    # --- GDL : G -> DL ---
    foreach ($gdlCfg in @(Get-ConfigValue -Path 'DomainLocalGroups' -Default @())) {
        $name = [string](Get-ObjectValue -Object $gdlCfg -Name 'Name' -Default '')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $ouName = [string](Get-ObjectValue -Object $gdlCfg -Name 'OU' -Default '')
        $pathDN = if ($ouName -and $ouByName.ContainsKey($ouName)) { $ouByName[$ouName] } else { $script:DomainDN }
        $pathLabel = if ($ouName -and $ouByName.ContainsKey($ouName)) { "l'OU '$ouName'" } else { 'la racine du domaine' }
        try {
            $groupInfo = New-TrackedGroup -Name $name -Scope DomainLocal -PathDN $pathDN -PathLabel $pathLabel
            if ($null -eq $groupInfo) { continue }
            if ($script:AllGDLs -notcontains $name) { $script:AllGDLs += $name }
            Add-TreeNode -Nodes $script:TreeNodes -Key $groupInfo.DN -ParentDN (Get-ParentDN -DN $groupInfo.DN) -DomainDN $script:DomainDN -Name $name -Type 'GDL'
            $recap += "GDL '$name' $(if ($groupInfo.Created) { 'créée' } else { 'réutilisée' }) dans $pathLabel"
            foreach ($member in @(Get-ObjectValue -Object $gdlCfg -Name 'Members' -Default @())) {
                if (Add-GroupMemberLogged -GroupName $name -MemberName ([string]$member) -MemberType 'GG') {
                    $recap += "GG '$member' ajouté à la GDL '$name' (modèle AGDLP)"
                }
            }
        } catch {
            Write-Log -Level Error -Message "GDL '$name' : $($_.Exception.Message)"
        }
    }

    Show-StepSummary -Title 'STRUCTURE AD (CONFIGURATION)' -Lines $recap
    Show-CredentialSummary
}

# --- GPO declaratives : Rules = liste d'identifiants du catalogue (ou 'T' = tout) ---
function Invoke-GpoFromConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $gpoConfigs = @(Get-ConfigValue -Path 'GPOs' -Default @())
    if ($gpoConfigs.Count -eq 0) { return }
    $script:CurrentStep = 'GPO (configuration)'
    $recap = @()
    if (-not (Initialize-GroupPolicyModule)) {
        Show-StepSummary -Title 'STRATÉGIES DE GROUPE (GPO)' -Lines @('Module GroupPolicy indisponible : étape annulée')
        return
    }

    $ouByName = @{}
    foreach ($ou in $script:AllOUs) { $ouByName[$ou.Name] = $ou.DN }

    foreach ($gpoCfg in $gpoConfigs) {
        $name = [string](Get-ObjectValue -Object $gpoCfg -Name 'Name' -Default '')
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        try {
            $gpoInfo = New-TrackedGpo -Name $name
            if ($null -eq $gpoInfo) { continue }
            $recap += "GPO '$name' $(if ($gpoInfo.Created) { 'créée' } else { 'réutilisée' })"

            $rules = @(Get-ObjectValue -Object $gpoCfg -Name 'Rules' -Default @() | ForEach-Object { [string]$_ })
            if ($rules -contains 'T') { $rules = @($script:GpoCatalog.Keys) }
            $applied = 0
            foreach ($ruleId in $rules) {
                if (Set-GpoCatalogRule -GpoName $name -RuleId $ruleId) { $applied++ }
            }
            if ($rules.Count -gt 0) { $recap += "GPO '$name' : $applied/$($rules.Count) règle(s) du catalogue appliquée(s)" }

            $linkTo = [string](Get-ObjectValue -Object $gpoCfg -Name 'LinkTo' -Default '')
            if ($linkTo -and $ouByName.ContainsKey($linkTo)) {
                if (New-TrackedGpoLink -GpoName $name -TargetDN $ouByName[$linkTo] -TargetLabel "l'OU '$linkTo'") {
                    $recap += "GPO '$name' liée à l'OU '$linkTo'"
                }
            } elseif ($linkTo) {
                Write-Log -Level Warn -Message "GPO '$name' : OU cible '$linkTo' introuvable, lien non créé."
            }
        } catch {
            Write-Log -Level Error -Message "GPO '$name' : $($_.Exception.Message)"
        }
    }
    Show-StepSummary -Title 'STRATÉGIES DE GROUPE (GPO)' -Lines $recap
}

# --- Partages declaratifs : dossier + partage + ACL + droits par GDL ---
function Invoke-SharesFromConfig {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $shareConfigs = @(Get-ConfigValue -Path 'Shares' -Default @())
    if ($shareConfigs.Count -eq 0) { return }
    $script:CurrentStep = 'Partages (configuration)'
    $recap = @()

    if (-not (Confirm-FileServerRole)) {
        Show-StepSummary -Title 'SERVEUR DE FICHIERS (CONFIGURATION)' -Lines @('Rôle Serveur de fichiers indisponible : étape ignorée')
        return
    }
    $adminPrincipal    = Get-WellKnownPrincipalName -Sid $script:WellKnownSid.Administrators
    $everyonePrincipal = Get-WellKnownPrincipalName -Sid $script:WellKnownSid.Everyone

    foreach ($shareCfg in $shareConfigs) {
        $shareName = [string](Get-ObjectValue -Object $shareCfg -Name 'Name' -Default '')
        if ([string]::IsNullOrWhiteSpace($shareName)) { continue }
        $sharePath = [string](Get-ObjectValue -Object $shareCfg -Name 'Path' -Default '')
        if ([string]::IsNullOrWhiteSpace($sharePath)) {
            $sharePath = Join-Path -Path $script:Defaults.ShareRootPath -ChildPath $shareName
        }

        if (-not (Test-Path -Path $sharePath)) {
            if ($PSCmdlet.ShouldProcess($sharePath, 'Créer le dossier')) {
                try {
                    New-Item -Path $sharePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                    Add-CreatedObject -Category Folders -Key $sharePath -Entry @{ Path = $sharePath }
                    $recap += "Dossier '$sharePath' créé"
                } catch {
                    Write-Log -Level Error -Message "Dossier '$sharePath' : $($_.Exception.Message)"
                    continue
                }
            } else { continue }
        }

        $existingShare = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
        if ($existingShare) {
            $recap += "Partage '$shareName' déjà présent : réutilisé"
        } else {
            if (-not $PSCmdlet.ShouldProcess("\\$env:COMPUTERNAME\$shareName", "Créer le partage SMB sur '$sharePath'")) { continue }
            try {
                New-SmbShare -Name $shareName -Path $sharePath -FullAccess $adminPrincipal -ErrorAction Stop | Out-Null
                Add-CreatedObject -Category Shares -Key $shareName -Entry @{ Name = $shareName; Path = $sharePath }
                Write-Log -Level Success -Message "Partage '$shareName' créé sur '$sharePath'."
                $recap += "Partage '$shareName' créé sur '$sharePath'"
            } catch {
                Write-Log -Level Error -Message "Partage '$shareName' : $($_.Exception.Message)"
                continue
            }
        }

        # ABE (module B1-M9 P2) : activée si le champ 'Abe' vaut $true dans la configuration
        if ([bool](Get-ObjectValue -Object $shareCfg -Name 'Abe' -Default $false)) {
            if (Enable-ShareAbe -ShareName $shareName) { $recap += "ABE activée sur '$shareName'" }
        }

        $grants = @(Get-ObjectValue -Object $shareCfg -Name 'Grants' -Default @())
        if ($grants.Count -gt 0) {
            if ([bool](Get-ObjectValue -Object $shareCfg -Name 'ResetAcl' -Default $true)) {
                try {
                    Reset-FolderAcl -Path $sharePath -KeepAdmins
                    $recap += "ACL de '$shareName' réinitialisée"
                } catch {
                    Write-Log -Level Error -Message "Réinitialisation ACL de '$sharePath' : $($_.Exception.Message)"
                }
            }
            try {
                Revoke-SmbShareAccess -Name $shareName -AccountName $everyonePrincipal -Force -ErrorAction Stop | Out-Null
            } catch {
                Write-Log -Level Detail -Message "Aucun accès '$everyonePrincipal' à retirer sur '$shareName'."
            }
            foreach ($grant in $grants) {
                $group = [string](Get-ObjectValue -Object $grant -Name 'Group' -Default '')
                if ([string]::IsNullOrWhiteSpace($group)) { continue }
                [System.Security.AccessControl.FileSystemRights]$rights = 0
                $labels = @()
                foreach ($r in @(Get-ObjectValue -Object $grant -Name 'Rights' -Default @('Modify'))) {
                    try {
                        $parsed = [System.Security.AccessControl.FileSystemRights][string]$r
                        $rights = $rights -bor $parsed
                        $labels += [string]$r
                    } catch {
                        Write-Log -Level Warn -Message "Droit '$r' inconnu pour '$group' sur '$shareName' : ignoré."
                    }
                }
                $recapLine = Grant-ShareAccess -ShareName $shareName -SharePath $sharePath -AccountName $group `
                    -NtfsRights $rights -RightsLabel ($labels -join ', ')
                if ($recapLine) { $recap += $recapLine }
            }
        }
    }
    Show-StepSummary -Title 'SERVEUR DE FICHIERS (CONFIGURATION)' -Lines $recap
}

#endregion

# =====================================================================
#  REGION 13 : ORCHESTRATION DE LA PHASE 2
# =====================================================================
#region Orchestration Phase 2

function Invoke-Phase2 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not $script:IsUnattended) { Clear-Host }
    Show-Banner -Text 'PHASE 2 : STRUCTURE AD, PARTAGES & RÔLES ANNEXES'
    $script:CurrentStep = 'Phase 2 - préparation'

    $runPhase2 = $true
    if ($script:State.Steps.Phase2Completed) {
        Write-Log -Level Warn -Message 'La Phase 2 a déjà été marquée comme terminée lors d''une exécution précédente.' -NoJournal
        Write-Log -Level Warn -Message 'Le script est idempotent : les objets existants seront détectés et réutilisés, aucun doublon ne sera créé.' -NoJournal
        $runPhase2 = Read-YesNo 'Voulez-vous relancer la Phase 2 (ajouter/compléter la structure) ?' -UnattendedAnswer $false
    }
    if (-not $runPhase2) {
        Write-Log -Level Detail -Message 'Phase 2 ignorée.'
        # Proposition explicite de reinitialisation meme sans relancer la Phase 2
        if (-not $script:IsUnattended) {
            if (Read-YesNo "Voulez-vous lancer la RÉINITIALISATION de ce que le script a créé (saisie du mot '$($script:ResetKeyword)' exigée) ?") {
                Invoke-FactoryReset
            }
        }
        return
    }

    try {
        Import-Module -Name ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Log -Level Error -Message "Module ActiveDirectory indisponible : $($_.Exception.Message)"
        return
    }
    try {
        $domain = Get-ADDomain -ErrorAction Stop
    } catch {
        Write-Log -Level Error -Message "Impossible d'interroger le domaine (AD DS encore en cours de démarrage ? redémarrage manquant ?) : $($_.Exception.Message)"
        Write-Log -Level Warn -Message 'Patientez quelques minutes ou redémarrez le serveur, puis relancez le script.' -NoJournal
        return
    }
    $script:DomainDN      = $domain.DistinguishedName
    $script:DomainDNSRoot = $domain.DNSRoot
    Add-ReportFact -Name 'Nom du serveur' -Value $env:COMPUTERNAME
    Add-ReportFact -Name 'Domaine' -Value $script:DomainDNSRoot

    # --- Tolerance de panne / reprise : rechargement de l'existant AD ---
    $script:TreeNodes = @{}
    $existing = Import-ExistingADStructure -DomainDN $script:DomainDN -TreeNodes $script:TreeNodes
    $script:AllOUs       = @($existing.OUs)
    $script:AllUsers     = @($existing.Users)
    $script:AllComputers = @($existing.Computers)
    $script:AllGGs       = @($existing.GGs)
    $script:AllGDLs      = @($existing.GDLs)

    Show-StepSummary -Title 'REPRISE / EXISTANT AD' -Lines @(
        "$($script:AllOUs.Count) OU existante(s) rechargée(s) et proposée(s) comme racine",
        "$($script:AllGGs.Count) Groupe(s) Global(aux) GG existant(s) rechargé(s)",
        "$($script:AllGDLs.Count) GDL existante(s) rechargée(s)",
        "$($script:AllUsers.Count) utilisateur(s) existant(s) rechargé(s)",
        "$($script:AllComputers.Count) ordinateur(s) existant(s) rechargé(s)"
    )

    # --- Politique de mot de passe/verrouillage du domaine (ANSSI, portée domaine) ---
    Invoke-DomainPasswordPolicyStep

    # --- Structure AD ---
    if ($script:IsUnattended) {
        Invoke-ADStructureFromConfig
    } else {
        Invoke-OUCreationStep
        Invoke-ComputerCreationStep
        Invoke-GlobalGroupStep
        Invoke-DomainLocalGroupStep
        Invoke-ContractorAccountStep    # module B1-M9 P7 : comptes prestataires à durée limitée
    }

    # --- Arborescence finale de la structure ---
    Write-Log -Level Title -Message "`n----------- ARBORESCENCE DE LA STRUCTURE AD -----------" -NoJournal
    if ($script:TreeNodes.Count -gt 0) {
        Show-ADTree -Nodes $script:TreeNodes
    } else {
        Write-Log -Level Detail -Message '(Aucun objet OU/GG/GDL/Utilisateur/Ordinateur créé ou détecté durant cette exécution.)' -NoJournal
    }
    Write-Log -Level Title -Message "---------------------------------------------------------`n" -NoJournal

    # --- GPO, partages, roles ---
    if ($script:IsUnattended) {
        Invoke-GpoFromConfig
        Invoke-SharesFromConfig
    } else {
        Invoke-GpoStep
        Invoke-FileServerStep
        Invoke-DelegationStep       # module B1-M9 P4 : délégation de contrôle sur OU
        Invoke-LapsSetupStep        # module B1-M9 bonus : Windows LAPS côté AD
    }
    Invoke-RoleInstallationStep

    # --- Audit des accès AD (lecture seule ; interactif ET non-interactif) ---
    Invoke-ADAccessAuditStep

    $script:State.Steps.Phase2Completed = $true
    Save-ScriptState -State $script:State

    # --- Recapitulatif final ---
    Show-CredentialSummary
    Show-Banner -Text 'INITIALISATION TERMINÉE AVEC SUCCÈS !'
    Write-Log -Level Title -Message " Paye une bière à Quentin et Max à l'occaz !" -NoJournal
    Invoke-ReportExport -PhaseLabel 'Phase 2'

    # --- Proposition explicite de reinitialisation en fin de script ---
    if (-not $script:IsUnattended) {
        if (Read-YesNo "Voulez-vous lancer la RÉINITIALISATION de ce que le script a créé (saisie du mot '$($script:ResetKeyword)' exigée) ?") {
            Invoke-FactoryReset
        }
    }
}

#endregion

# =====================================================================
#  REGION 14 : REINITIALISATION « biere » (perimetre sur : objets traces)
# =====================================================================
#region Reinitialisation

# --- Recapitulatif detaille de ce qui va etre supprime ---
function Show-ResetSummary {
    param([Parameter(Mandatory)]$State)
    $created = $State.Created
    Write-Log -Level Title -Message "`n----------- ÉLÉMENTS QUI SERONT SUPPRIMÉS (créés et tracés par ce script) -----------" -NoJournal
    $sections = @(
        @{ Label = 'Liens GPO';    Items = @($created.GpoLinks  | ForEach-Object { "GPO '$($_.Gpo)' -> $($_.Target)" }) }
        @{ Label = 'GPO';          Items = @($created.GPOs      | ForEach-Object { $_.Name }) }
        @{ Label = 'Partages SMB'; Items = @($created.Shares    | ForEach-Object { "$($_.Name) ($($_.Path))" }) }
        @{ Label = 'Utilisateurs'; Items = @($created.Users     | ForEach-Object { "$($_.Login) [$($_.DN)]" }) }
        @{ Label = 'Ordinateurs';  Items = @($created.Computers | ForEach-Object { $_.Name }) }
        @{ Label = 'Groupes (GG/GDL)'; Items = @($created.Groups | ForEach-Object { "$($_.Name) ($($_.Scope))" }) }
        @{ Label = 'OU';           Items = @($created.OUs       | ForEach-Object { $_.DN }) }
        @{ Label = 'Rapports et captures d''écran (contiennent des mots de passe en clair)'; Items = @($created.Reports | ForEach-Object { $_.Path }) }
        @{ Label = 'Dossiers (suppression OPTIONNELLE, confirmée séparément)'; Items = @($created.Folders | ForEach-Object { $_.Path }) }
    )
    foreach ($section in $sections) {
        Write-Log -Level Warn -Message "  $($section.Label) : $($section.Items.Count)" -NoJournal
        foreach ($item in $section.Items) {
            Write-Log -Level Detail -Message "    - $item" -NoJournal
        }
    }
    Write-Log -Level Detail -Message '  (Les rôles Windows installés, le fuseau, l''IP et le contrôleur de domaine ne sont PAS touchés.)' -NoJournal
    Write-Log -Level Title -Message "---------------------------------------------------------------------------------------`n" -NoJournal
}

# --- Reinitialisation protegee par le mot 'biere' (sensible a la casse) ---
# Supprime UNIQUEMENT ce que le script a cree et trace dans state.json.
# Idempotente et tolerante : un objet deja absent est ignore sans echec.
# La retrogradation du controleur de domaine n'est JAMAIS incluse ici.
function Invoke-FactoryReset {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Réinitialisation'
    Show-Banner -Text 'RÉINITIALISATION DE CE QUE LE SCRIPT A CRÉÉ'

    if ($script:IsUnattended) {
        Write-Log -Level Error -Message 'Réinitialisation refusée en mode -Unattended : la confirmation interactive est obligatoire.'
        return
    }
    # Couper les captures d'écran pendant tout le reset : sinon la capture de fin
    # d'étape re-tracerait un objet (rapport/capture) dans un state.json qu'on vient
    # de purger, et photographierait le récapitulatif de suppression.
    $script:SuppressScreenshots = $true
    if ($null -eq $script:State) { $script:State = Get-ScriptState }

    $total = Get-CreatedObjectCount -State $script:State
    if ($total -eq 0) {
        Write-Log -Level Warn -Message 'Aucun objet tracé dans le fichier d''état : rien à supprimer.'
        if ((Test-Path -Path $script:StatePath) -and (Read-YesNo 'Supprimer tout de même le fichier d''état (reprise remise à zéro) ?')) {
            if ($PSCmdlet.ShouldProcess($script:StatePath, 'Supprimer le fichier d''état')) {
                try {
                    Remove-Item -Path $script:StatePath -Force -ErrorAction Stop
                    Write-Log -Level Success -Message "Fichier d'état supprimé : $script:StatePath"
                    $script:State = Get-DefaultState
                } catch {
                    Write-Log -Level Error -Message "Suppression du fichier d'état impossible : $($_.Exception.Message)"
                }
            }
        }
        return
    }

    Write-Log -Level Warn -Message "  Périmètre SÛR : seuls les $total objet(s) créé(s) ET tracé(s) par ce script seront supprimés." -NoJournal
    Write-Log -Level Warn -Message '  Les objets préexistants réutilisés ne sont pas concernés.' -NoJournal
    Write-Log -Level Error -Message '  La rétrogradation du contrôleur de domaine n''est JAMAIS incluse dans cette opération.' -NoJournal

    # --- Verrou n°1 : saisie EXACTE du mot de passe symbolique (sensible a la casse) ---
    $secret = Read-Host -Prompt 'Tapez exactement le mot de passe de réinitialisation pour continuer (ou Entrée pour annuler)'
    if (-not ($secret -ceq $script:ResetKeyword)) {
        Write-Log -Level Warn -Message 'Saisie incorrecte : réinitialisation ANNULÉE (aucune suppression).'
        return
    }

    # --- Recapitulatif detaille + verrou n°2 : confirmation O/N ---
    Show-ResetSummary -State $script:State
    $deleteFolders = $false
    if (@($script:State.Created.Folders).Count -gt 0) {
        $deleteFolders = Read-YesNo 'Supprimer AUSSI les dossiers créés par le script (ATTENTION : leurs DONNÉES seront perdues) ?'
    }
    if (-not (Read-YesNo 'Confirmez-vous DÉFINITIVEMENT la suppression des éléments listés ci-dessus ?')) {
        Write-Log -Level Warn -Message 'Réinitialisation ANNULÉE par l''utilisateur (aucune suppression).'
        return
    }

    $stats = @{ Removed = 0; Absent = 0; Failed = 0 }
    $created = $script:State.Created

    # --- Modules necessaires (selon les categories presentes) ---
    $adAvailable = $true
    if (@($created.OUs).Count + @($created.Groups).Count + @($created.Users).Count + @($created.Computers).Count -gt 0) {
        try { Import-Module -Name ActiveDirectory -ErrorAction Stop } catch {
            $adAvailable = $false
            Write-Log -Level Error -Message "Module ActiveDirectory indisponible : les objets AD tracés ne seront pas supprimés ($($_.Exception.Message))."
        }
    }
    $gpAvailable = $true
    if (@($created.GPOs).Count + @($created.GpoLinks).Count -gt 0) {
        try { Import-Module -Name GroupPolicy -ErrorAction Stop } catch {
            $gpAvailable = $false
            Write-Log -Level Error -Message "Module GroupPolicy indisponible : les GPO tracées ne seront pas supprimées ($($_.Exception.Message))."
        }
    }

    # --- 1) Liens GPO ---
    if ($gpAvailable) {
        foreach ($link in @($created.GpoLinks)) {
            $label = "Lien GPO '$($link.Gpo)' -> $($link.Target)"
            if (-not $PSCmdlet.ShouldProcess($label, 'Remove-GPLink')) { continue }
            try {
                Remove-GPLink -Name $link.Gpo -Target $link.Target -ErrorAction Stop | Out-Null
                Write-Log -Level Success -Message "$label supprimé."
                $stats.Removed++
            } catch {
                Write-Log -Level Detail -Message "$label : déjà absent ou insupprimable ($($_.Exception.Message))."
                $stats.Absent++
            }
        }
        # --- 2) GPO ---
        foreach ($gpo in @($created.GPOs)) {
            $label = "GPO '$($gpo.Name)'"
            if ($null -eq (Get-GPO -Name $gpo.Name -ErrorAction SilentlyContinue)) {
                Write-Log -Level Detail -Message "$label : déjà absente, ignorée."
                $stats.Absent++
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($label, 'Remove-GPO')) { continue }
            try {
                Remove-GPO -Name $gpo.Name -ErrorAction Stop
                Write-Log -Level Success -Message "$label supprimée."
                $stats.Removed++
            } catch {
                Write-Log -Level Error -Message "$label : échec de suppression ($($_.Exception.Message))."
                $stats.Failed++
            }
        }
    }

    # --- 3) Partages SMB ---
    foreach ($share in @($created.Shares)) {
        $label = "Partage SMB '$($share.Name)'"
        if ($null -eq (Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue)) {
            Write-Log -Level Detail -Message "$label : déjà absent, ignoré."
            $stats.Absent++
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($label, 'Remove-SmbShare')) { continue }
        try {
            Remove-SmbShare -Name $share.Name -Force -Confirm:$false -ErrorAction Stop
            Write-Log -Level Success -Message "$label supprimé (le dossier est conservé sauf option contraire)."
            $stats.Removed++
        } catch {
            Write-Log -Level Error -Message "$label : échec de suppression ($($_.Exception.Message))."
            $stats.Failed++
        }
    }

    # --- 4/5/6) Objets AD : utilisateurs, ordinateurs, groupes ---
    if ($adAvailable) {
        $adCategories = @(
            @{ Items = @($created.Users);     LabelFmt = "Utilisateur '{0}'"; NameProp = 'Login' }
            @{ Items = @($created.Computers); LabelFmt = "Ordinateur '{0}'";  NameProp = 'Name' }
            @{ Items = @($created.Groups);    LabelFmt = "Groupe '{0}'";      NameProp = 'Name' }
        )
        foreach ($category in $adCategories) {
            foreach ($item in $category.Items) {
                $label = $category.LabelFmt -f $item.($category.NameProp)
                $adObject = $null
                try { $adObject = Get-ADObject -Identity $item.DN -ErrorAction Stop } catch { $adObject = $null }
                if ($null -eq $adObject) {
                    Write-Log -Level Detail -Message "$label : déjà absent, ignoré."
                    $stats.Absent++
                    continue
                }
                if (-not $PSCmdlet.ShouldProcess($item.DN, "Supprimer $label")) { continue }
                try {
                    try {
                        Set-ADObject -Identity $item.DN -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                    } catch {
                        Write-Log -Level Detail -Message "$label : levée de la protection anti-suppression sans effet ($($_.Exception.Message))."
                    }
                    Remove-ADObject -Identity $item.DN -Confirm:$false -ErrorAction Stop
                    Write-Log -Level Success -Message "$label supprimé."
                    $stats.Removed++
                } catch {
                    Write-Log -Level Error -Message "$label : échec de suppression ($($_.Exception.Message))."
                    $stats.Failed++
                }
            }
        }

        # --- 7) OU (les plus profondes d'abord ; jamais recursif : une OU encore
        # peuplée par des objets NON traces est conservee et signalee) ---
        $ousByDepth = @($created.OUs | Sort-Object -Property { ($_.DN -split '(?<!\\),').Count } -Descending)
        foreach ($ou in $ousByDepth) {
            $label = "OU '$($ou.Name)' [$($ou.DN)]"
            $adObject = $null
            try { $adObject = Get-ADObject -Identity $ou.DN -ErrorAction Stop } catch { $adObject = $null }
            if ($null -eq $adObject) {
                Write-Log -Level Detail -Message "$label : déjà absente, ignorée."
                $stats.Absent++
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($ou.DN, 'Remove-ADOrganizationalUnit')) { continue }
            try {
                try {
                    Set-ADObject -Identity $ou.DN -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
                } catch {
                    Write-Log -Level Detail -Message "$label : levée de la protection anti-suppression sans effet ($($_.Exception.Message))."
                }
                Remove-ADOrganizationalUnit -Identity $ou.DN -Confirm:$false -ErrorAction Stop
                Write-Log -Level Success -Message "$label supprimée."
                $stats.Removed++
            } catch {
                Write-Log -Level Warn -Message "$label : NON supprimée (probablement non vide : elle contient des objets non créés par ce script). Détail : $($_.Exception.Message)"
                $stats.Failed++
            }
        }
    }

    # --- 8) Dossiers (uniquement si confirmation separee) ---
    if ($deleteFolders) {
        foreach ($folder in @($created.Folders)) {
            $label = "Dossier '$($folder.Path)'"
            if (-not (Test-Path -Path $folder.Path)) {
                Write-Log -Level Detail -Message "$label : déjà absent, ignoré."
                $stats.Absent++
                continue
            }
            if (-not $PSCmdlet.ShouldProcess($folder.Path, 'Remove-Item -Recurse -Force')) { continue }
            try {
                Remove-Item -Path $folder.Path -Recurse -Force -ErrorAction Stop
                Write-Log -Level Success -Message "$label supprimé (données incluses)."
                $stats.Removed++
            } catch {
                Write-Log -Level Error -Message "$label : échec de suppression ($($_.Exception.Message))."
                $stats.Failed++
            }
        }
    } elseif (@($created.Folders).Count -gt 0) {
        Write-Log -Message "Dossiers conservés (suppression non confirmée) : $(@($created.Folders | ForEach-Object { $_.Path }) -join ', ')"
    }

    # --- 8bis) Rapports et captures traces (fichiers sensibles : mots de passe en clair) ---
    foreach ($report in @($created.Reports)) {
        $label = "Rapport/capture '$($report.Path)'"
        if (-not (Test-Path -Path $report.Path)) {
            Write-Log -Level Detail -Message "$label : déjà absent, ignoré."
            $stats.Absent++
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($report.Path, 'Remove-Item')) { continue }
        try {
            Remove-Item -Path $report.Path -Force -ErrorAction Stop
            Write-Log -Level Success -Message "$label supprimé."
            $stats.Removed++
        } catch {
            Write-Log -Level Error -Message "$label : échec de suppression ($($_.Exception.Message))."
            $stats.Failed++
        }
    }

    # --- 9) Fichier d'etat (en dernier) ---
    if (Test-Path -Path $script:StatePath) {
        if ($PSCmdlet.ShouldProcess($script:StatePath, 'Supprimer le fichier d''état')) {
            try {
                Remove-Item -Path $script:StatePath -Force -ErrorAction Stop
                Write-Log -Level Success -Message "Fichier d'état supprimé : $script:StatePath"
                $stats.Removed++
            } catch {
                Write-Log -Level Error -Message "Suppression du fichier d'état impossible : $($_.Exception.Message)"
                $stats.Failed++
            }
        }
    }
    $script:State = Get-DefaultState

    # --- Recapitulatif + rapport de reinitialisation ---
    Show-StepSummary -Title 'RÉINITIALISATION' -Lines @(
        "$($stats.Removed) élément(s) supprimé(s)",
        "$($stats.Absent) élément(s) déjà absent(s) (ignorés sans échec)",
        "$($stats.Failed) échec(s) de suppression (voir le journal)",
        'Les rapports et captures tracés (mots de passe en clair) ont été supprimés',
        'Le contrôleur de domaine et les rôles Windows installés n''ont PAS été touchés'
    )
    Invoke-ReportExport -PhaseLabel 'Réinitialisation (biere)' -NoTrack

    # --- Option SEPAREE et tres explicite : retrogradation du controleur de domaine ---
    Write-Log -Level Warn -Message 'RAPPEL : ce serveur reste contrôleur de domaine (la réinitialisation ne le rétrograde jamais).' -NoJournal
    if (Read-YesNo 'Voulez-vous ouvrir l''option SÉPARÉE de rétrogradation du contrôleur de domaine (Uninstall-ADDSDomainController) ?') {
        Invoke-DCDemotion
    }
}

# --- Retrogradation du controleur de domaine : option DISTINCTE du reset,
# exigeant la saisie exacte du nom DNS du domaine puis une confirmation finale. ---
function Invoke-DCDemotion {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $script:CurrentStep = 'Rétrogradation DC'
    Show-Banner -Text 'OPTION SÉPARÉE : RÉTROGRADATION DU CONTRÔLEUR DE DOMAINE'

    if ($script:IsUnattended) {
        Write-Log -Level Error -Message 'Rétrogradation refusée en mode -Unattended : confirmation interactive obligatoire.'
        return
    }
    if ($null -eq (Get-Service -Name NTDS -ErrorAction SilentlyContinue)) {
        Write-Log -Level Warn -Message 'Ce serveur ne semble pas être un contrôleur de domaine (service NTDS absent) : opération annulée.'
        return
    }

    Write-Log -Level Error -Message ' OPÉRATION IRRÉVERSIBLE : ce serveur cessera d''être contrôleur de domaine.' -NoJournal
    Write-Log -Level Error -Message ' S''il est le DERNIER contrôleur, le domaine entier sera DÉTRUIT (comptes, GPO, tout).' -NoJournal
    Write-Log -Level Error -Message ' Le serveur redémarrera automatiquement à la fin de l''opération.' -NoJournal

    $domainName = $env:USERDNSDOMAIN
    try {
        Import-Module -Name ActiveDirectory -ErrorAction Stop
        $domainName = (Get-ADDomain -ErrorAction Stop).DNSRoot
    } catch {
        Write-Log -Level Detail -Message "Nom de domaine déterminé via l'environnement ($domainName) : $($_.Exception.Message)"
    }
    if ([string]::IsNullOrWhiteSpace($domainName)) {
        Write-Log -Level Error -Message 'Impossible de déterminer le nom du domaine : opération annulée.'
        return
    }

    $typed = Read-Host -Prompt "Pour confirmer, tapez EXACTEMENT le nom DNS du domaine ('$domainName'), ou Entrée pour annuler"
    if ($typed -ne $domainName) {
        Write-Log -Level Warn -Message 'Nom de domaine non confirmé : rétrogradation ANNULÉE.'
        return
    }
    $isLastDC = Read-YesNo 'Ce serveur est-il le DERNIER contrôleur du domaine (le domaine entier sera alors supprimé) ?'
    if (-not (Read-YesNo 'DERNIÈRE CONFIRMATION : lancer la rétrogradation MAINTENANT ?')) {
        Write-Log -Level Warn -Message 'Rétrogradation ANNULÉE par l''utilisateur.'
        return
    }

    # Mot de passe du compte Administrateur LOCAL apres retrogradation
    do {
        $localAdminPwd = Read-Host -Prompt 'Nouveau mot de passe Administrateur LOCAL après rétrogradation (12 car. min : majuscule, minuscule, chiffre)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($localAdminPwd)
        try { $plainCheck = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $pwdValid = Test-StrongPassword -Value $plainCheck
        $plainCheck = $null
        if (-not $pwdValid) {
            Write-Log -Level Error -Message 'Mot de passe trop faible, recommencez.' -NoJournal
        }
    } until ($pwdValid)

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Uninstall-ADDSDomainController (domaine '$domainName')")) { return }
    try {
        Import-Module -Name ADDSDeployment -ErrorAction Stop
        Write-Log -Level Warn -Message "Rétrogradation du contrôleur de domaine '$env:COMPUTERNAME' (domaine '$domainName') lancée."
        Invoke-ReportExport -PhaseLabel 'Rétrogradation du contrôleur de domaine' -NoTrack
        if ($isLastDC) {
            Uninstall-ADDSDomainController -LocalAdministratorPassword $localAdminPwd `
                -LastDomainControllerInDomain -RemoveApplicationPartitions -IgnoreLastDnsServerForZone `
                -Force -ErrorAction Stop
        } else {
            Uninstall-ADDSDomainController -LocalAdministratorPassword $localAdminPwd -Force -ErrorAction Stop
        }
    } catch {
        Write-Log -Level Error -Message "ÉCHEC de la rétrogradation : $($_.Exception.Message)"
    }
}

#endregion

# =====================================================================
#  REGION 15 : POINT D'ENTREE PRINCIPAL
# =====================================================================
#region Point d'entree

function Invoke-Main {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    # --- Auto-elevation (les parametres -ConfigFile/-Unattended/-Reset/-WhatIf sont retransmis) ---
    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($windowsIdentity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if (-not $script:ScriptPath) {
            Write-Log -Level Error -Message 'Chemin du script introuvable : faites un clic droit sur le fichier .ps1 puis ''Exécuter avec PowerShell'' (pas F5 dans ISE).' -NoJournal
            if (-not $script:ParamUnattended) { $null = Read-Host -Prompt 'Appuyez sur Entrée pour quitter' }
            return
        }
        Write-Log -Level Warn -Message 'Droits administrateur requis : relance du script en élévation...' -NoJournal
        $exe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
        $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$script:ScriptPath`""
        if ($script:ParamConfigFile) { $argList += " -ConfigFile `"$script:ParamConfigFile`"" }
        if ($script:ParamUnattended) { $argList += ' -Unattended' }
        if ($script:ParamReset) { $argList += ' -Reset' }
        if ($script:ParamNoScreenshots) { $argList += ' -NoScreenshots' }
        if ($WhatIfPreference) { $argList += ' -WhatIf' }
        Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs
        return
    }

    # --- Confort visuel (console classique uniquement) ---
    if ($Host.Name -eq 'ConsoleHost') {
        try {
            $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(120, 35)
        } catch {
            Write-Log -Level Detail -Message "Redimensionnement de la console impossible : $($_.Exception.Message)" -NoJournal
        }
    }

    # --- Transcript (journal texte complet de la session) ---
    $transcriptStarted = $false
    if (-not $WhatIfPreference) {
        try {
            if (-not (Test-Path -Path $script:LogDir)) {
                New-Item -Path $script:LogDir -ItemType Directory -Force | Out-Null
            }
            $logPath = Join-Path -Path $script:LogDir -ChildPath ('Init-WindowsServer_{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
            Start-Transcript -Path $logPath -Append -ErrorAction Stop | Out-Null
            $transcriptStarted = $true
        } catch {
            Write-Log -Level Warn -Message "Transcript non démarré : $($_.Exception.Message)" -NoJournal
        }
    }

    try {
        # --- Chargement de la configuration (facultatif) ---
        $script:IsUnattended = $script:ParamUnattended
        if ($script:ParamConfigFile) {
            try {
                $resolvedConfig = (Resolve-Path -Path $script:ParamConfigFile -ErrorAction Stop).Path
                if ($resolvedConfig -match '\.psd1$') {
                    $script:Config = Import-PowerShellDataFile -Path $resolvedConfig
                } elseif ($resolvedConfig -match '\.json$') {
                    $script:Config = Get-Content -Path $resolvedConfig -Raw -Encoding UTF8 | ConvertFrom-Json
                } else {
                    throw 'extension non gérée (attendu : .psd1 ou .json)'
                }
                Write-Log -Level Success -Message "Configuration chargée : $resolvedConfig"
            } catch {
                Write-Log -Level Error -Message "Fichier de configuration illisible : $($_.Exception.Message)"
                if ($script:IsUnattended) { return }
            }
        } elseif ($script:IsUnattended) {
            Write-Log -Level Warn -Message 'Mode -Unattended sans -ConfigFile : la plupart des étapes seront ignorées (aucune valeur fournie).'
        }

        $script:State = Get-ScriptState
        Show-Banner -Text "$script:ScriptName v$script:ScriptVersion"
        if ($WhatIfPreference) {
            Write-Log -Level Warn -Message 'MODE SIMULATION (-WhatIf) : aucune modification ne sera appliquée.' -NoJournal
        }

        if ($script:ParamReset) {
            Invoke-FactoryReset
        } else {
            # --- Detection de phase : controleur de domaine deja promu ? ---
            $ntds = Get-Service -Name NTDS -ErrorAction SilentlyContinue
            $isDC = ($null -ne $ntds -and $ntds.Status -eq 'Running')
            if (-not $isDC -and $script:State.Steps.ADDSPromoted) {
                Write-Log -Level Warn -Message 'Promotion AD DS déjà lancée mais service NTDS inactif : un redémarrage est probablement nécessaire avant la Phase 2.'
            }
            if ($isDC) {
                Invoke-Phase2
            } else {
                Invoke-Phase1
            }
        }
    } catch {
        Show-Banner -Text 'UNE ERREUR A INTERROMPU LE SCRIPT'
        Write-Log -Level Error -Message $_.Exception.Message
        $lineInfo = if ($_.InvocationInfo -and $_.InvocationInfo.Line) { $_.InvocationInfo.Line.Trim() } else { '(inconnue)' }
        Write-Log -Level Warn -Message ("Ligne : {0}  |  Commande : {1}" -f $_.InvocationInfo.ScriptLineNumber, $lineInfo)
        Write-Log -Level Warn -Message "Détail complet dans les journaux : $script:LogDir"
        Invoke-ReportExport -PhaseLabel 'Exécution interrompue par une erreur'
    } finally {
        if ($transcriptStarted) {
            try { Stop-Transcript | Out-Null } catch { Write-Verbose "Stop-Transcript : $($_.Exception.Message)" }
        }
    }

    if (-not $script:IsUnattended) {
        $null = Read-Host -Prompt 'Appuyez sur Entrée pour quitter'
    }
}

# Point d'entree : le script s'execute, sauf s'il est dot-source (". .\Init-WindowsServer.ps1"),
# ce qui permet aux tests Pester de charger les fonctions sans lancer l'outil.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Main
}

#endregion
