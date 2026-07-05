@{
    # =================================================================
    # Fichier de configuration d'exemple pour Init-WindowsServer.ps1
    # Usage : .\Init-WindowsServer.ps1 -ConfigFile .\config.sample.psd1 -Unattended
    # (format .json equivalent egalement accepte)
    # NE COMMITEZ JAMAIS un fichier de configuration contenant des mots
    # de passe reels : laissez les champs vides pour une generation aleatoire.
    # =================================================================

    # --- Phase 1 ---
    InstallUpdates = $false          # $true : installe les mises a jour (PSWindowsUpdate)
    AutoReboot     = $true           # $true : redemarre automatiquement quand necessaire (mode unattended)
    ServerName     = 'SRV-AD-01'     # vide ou identique au nom actuel : pas de renommage
    TimeZoneId     = 'Romance Standard Time'   # Paris ; lister : Get-TimeZone -ListAvailable

    Network = @{
        InterfaceAlias = ''          # vide : la carte active unique est choisie automatiquement
        IPAddress      = '192.168.10.10'
        PrefixLength   = 24
        Gateway        = '192.168.10.254'      # vide : pas de passerelle
        DnsServers     = @('127.0.0.1')        # vide : DNS inchanges
    }

    Domain = @{
        Name         = 'entreprise.local'      # vide : pas de promotion AD DS
        DsrmPassword = ''            # vide : genere aleatoirement et consigne dans le rapport
    }

    # --- Phase 2 : mots de passe des utilisateurs crees ---
    Users = @{
        PasswordMode   = 'Random'    # 'Random' (un mot de passe par utilisateur) ou 'Common'
        CommonPassword = ''          # requis seulement si PasswordMode = 'Common' (12 car. min)
        PasswordLength = 14
    }

    # --- Phase 2 : politique de mot de passe / verrouillage du DOMAINE (ANSSI) ---
    # Appliquee au domaine entier via Set-ADDefaultDomainPasswordPolicy. Apply=$false
    # laisse la politique du domaine inchangee. Valeurs alignees ANSSI / module B1-M8.
    DomainPasswordPolicy = @{
        Apply              = $false   # $true pour appliquer la politique ci-dessous
        MinLength          = 12       # ANSSI >= 12 (16 pour acces distant/comptes sensibles)
        Complexity         = $true
        HistoryCount       = 24
        MaxAgeDays         = 90       # 0 = pas d'expiration
        MinAgeDays         = 1
        LockoutThreshold   = 5        # module B1-M8 : 5 (3 pour acces distant)
        LockoutDurationMin = 15
        LockoutWindowMin   = 15
    }

    # --- Phase 2 : audit des acces AD (module B1-M9, lecture seule) ---
    # Liste les membres des groupes privilegies, les comptes dormants et a risque.
    # Aucune modification. Fonctionne aussi en mode -Unattended.
    AccessAudit = @{
        Enabled     = $false   # $true pour lancer l'audit en fin de Phase 2
        DormantDays = 90       # seuil des comptes "dormants" (jours sans connexion)
    }

    # NB : les etapes prestataires (comptes a duree limitee), delegation de controle
    # sur OU et preparation Windows LAPS sont INTERACTIVES (module B1-M9) : elles ne
    # sont pas pilotees par ce fichier et n'apparaissent qu'en execution interactive.

    # --- Phase 2 : structure AD (modele AGDLP) ---
    # L'ordre des OU definit la hierarchie : 'Parent' reference une OU declaree AVANT.
    OUs = @(
        @{
            Name   = 'Siege'
            Parent = ''
            Users  = @(
                @{ FirstName = 'Jean';  LastName = 'Dupont'; Login = 'jdupont' }
                @{ FirstName = 'Marie'; LastName = 'Curie';  Login = 'mcurie' }
            )
        }
        @{
            Name   = 'Direction'
            Parent = 'Siege'
            Users  = @()
        }
    )

    Computers = @(
        @{ Name = 'PC-DIR-01'; OU = 'Direction' }
    )

    GlobalGroups = @(
        @{ Name = 'GG_Direction'; OU = 'Direction'; Members = @('jdupont', 'mcurie') }
    )

    DomainLocalGroups = @(
        @{ Name = 'GDL_Direction_RW'; OU = 'Direction'; Members = @('GG_Direction') }
    )

    # --- Phase 2 : GPO ---
    # Rules : identifiants du catalogue integre (9 categories, 39 regles) ou 'T' pour tout.
    #   1.x securite du poste (UAC, pare-feu, BitLocker)   2.x reseau ANSSI (SMB, LLMNR, RDP NLA)
    #   3.x audit/journaux   4.x gestion des postes (LAPS, WSUS, USB)   5.x restrictions utilisateurs
    #   6.x verrouillage/banniere   7.x reduction surface d'attaque   8.x protection des identifiants
    #   9.x defense du poste (SmartScreen, Defender, audit avance)
    # La regle 4.2 (WSUS) n'est appliquee QUE si WsusUrl ci-dessous est renseignee.
    WsusUrl = ''                     # ex: 'http://srv-wsus:8530'
    GPOs = @(
        # Exemple : pack de durcissement ANSSI + mesures du module B1-M8
        @{ Name = 'GPO_Durcissement_ANSSI'; Rules = @('1.4','2.2','2.4','2.5','2.6','3.1','3.2','8.1','8.2','8.4','9.1'); LinkTo = 'Siege' }
        @{ Name = 'GPO_Postes_B1M8';        Rules = @('1.5','4.5','6.3','7.4'); LinkTo = 'Direction' }
    )

    # --- Phase 2 : partages (droits accordes aux GDL uniquement : modele AGDLP) ---
    # Rights : noms de l'enum FileSystemRights (FullControl, Modify, ReadAndExecute, Read, Write...)
    Shares = @(
        @{
            Name     = 'Direction'
            Path     = 'C:\Partages\Direction'   # vide : C:\Partages\<Name>
            ResetAcl = $true                     # heritage NTFS desactive + ACL repartant de zero
            Abe      = $true                     # module B1-M9 : enumeration basee sur l'acces (ABE)
            Grants   = @(
                @{ Group = 'GDL_Direction_RW'; Rights = @('Modify') }
            )
        }
    )

    # --- Phase 2 : roles optionnels ---
    # Valeurs possibles : DHCP, UpdateServices, RDS-RD-Server, Web-Server, Hyper-V
    Roles = @()

    # --- Rapport d'execution (PDF + captures d'ecran) ---
    # ATTENTION : le rapport PDF contient les mots de passe EN CLAIR. Stockez le
    # dossier en lieu sur et excluez-le de tout depot Git (voir .gitignore fourni).
    Report = @{
        Directory     = 'C:\Rapports'   # rapports .pdf/.txt et sous-dossier captures\
        NoScreenshots = $false          # $true : desactive les captures d'ecran (Server Core)
    }
}
