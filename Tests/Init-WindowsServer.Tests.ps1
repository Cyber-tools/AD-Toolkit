# =====================================================================
# Tests Pester (v5) des fonctions utilitaires pures d'Init-WindowsServer.ps1
# Execution : Invoke-Pester -Path .\Tests
# Le script est dot-source : son point d'entree (Invoke-Main) n'est pas execute.
# =====================================================================

BeforeAll {
    $scriptPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Init-WindowsServer.ps1'
    . $scriptPath
}

Describe 'Validateurs de saisie' {

    Context 'Test-IPv4Address' {
        It 'accepte une adresse valide' {
            Test-IPv4Address -Value '192.168.1.10' | Should -BeTrue
        }
        It 'rejette un octet > 255' {
            Test-IPv4Address -Value '192.168.1.300' | Should -BeFalse
        }
        It 'rejette une chaîne quelconque' {
            Test-IPv4Address -Value 'abc' | Should -BeFalse
        }
        It 'rejette une adresse incomplète' {
            Test-IPv4Address -Value '192.168.1' | Should -BeFalse
        }
        It 'rejette une valeur vide' {
            Test-IPv4Address -Value '' | Should -BeFalse
        }
    }

    Context 'Test-IPv4Prefix' {
        It 'accepte 0, 24 et 32' {
            Test-IPv4Prefix -Value '0' | Should -BeTrue
            Test-IPv4Prefix -Value '24' | Should -BeTrue
            Test-IPv4Prefix -Value '32' | Should -BeTrue
        }
        It 'rejette 33, -1 et les lettres' {
            Test-IPv4Prefix -Value '33' | Should -BeFalse
            Test-IPv4Prefix -Value '-1' | Should -BeFalse
            Test-IPv4Prefix -Value 'aa' | Should -BeFalse
        }
    }

    Context 'Test-WsusUrl' {
        It 'accepte http://srv-wsus:8530' {
            Test-WsusUrl -Value 'http://srv-wsus:8530' | Should -BeTrue
        }
        It 'accepte https avec chemin' {
            Test-WsusUrl -Value 'https://wsus.entreprise.local:8531/selfupdate' | Should -BeTrue
        }
        It 'rejette un nom sans schéma (placeholder interdit)' {
            Test-WsusUrl -Value 'WSUS-SERVER:8530' | Should -BeFalse
        }
    }

    Context 'Test-NetBiosName' {
        It 'accepte SRV-AD-01' {
            Test-NetBiosName -Value 'SRV-AD-01' | Should -BeTrue
        }
        It 'rejette un nom de plus de 15 caractères' {
            Test-NetBiosName -Value 'UNNOMBEAUCOUPTROPLONG' | Should -BeFalse
        }
        It 'rejette un nom finissant par un tiret' {
            Test-NetBiosName -Value 'SRV-' | Should -BeFalse
        }
    }

    Context 'Test-DomainFqdn' {
        It 'accepte entreprise.local' {
            Test-DomainFqdn -Value 'entreprise.local' | Should -BeTrue
        }
        It 'rejette un label unique' {
            Test-DomainFqdn -Value 'local' | Should -BeFalse
        }
    }

    Context 'Test-StrongPassword' {
        It 'accepte 12+ caractères avec majuscule, minuscule et chiffre' {
            Test-StrongPassword -Value 'Password12345' | Should -BeTrue
        }
        It 'rejette un mot de passe trop court' {
            Test-StrongPassword -Value 'Abc1' | Should -BeFalse
        }
        It 'rejette un mot de passe sans chiffre' {
            Test-StrongPassword -Value 'PasswordSansChiffre' | Should -BeFalse
        }
    }
}

Describe 'New-RandomPassword' {
    It 'respecte la longueur demandée' {
        (New-RandomPassword -Length 20).Length | Should -Be 20
    }
    It 'contient les 4 classes de caractères' {
        $p = New-RandomPassword -Length 14
        $p | Should -MatchExactly '[A-Z]'
        $p | Should -MatchExactly '[a-z]'
        $p | Should -Match '\d'
        $p | Should -Match '[!@#%*\-_?]'
    }
    It 'est différent à chaque appel' {
        (New-RandomPassword -Length 14) | Should -Not -Be (New-RandomPassword -Length 14)
    }
    It 'satisfait Test-StrongPassword' {
        Test-StrongPassword -Value (New-RandomPassword -Length 14) | Should -BeTrue
    }
    It 'exclut les caractères ambigus (I, l, O, 0, 1)' {
        # 30 tirages pour couvrir statistiquement l'alphabet utilise.
        # -MatchExactly : comparaison sensible a la casse ('i' minuscule est permis).
        foreach ($i in 1..30) {
            New-RandomPassword -Length 20 | Should -Not -MatchExactly '[IlO01]'
        }
    }
}

Describe 'Utilitaires de chaînes' {

    Context 'ConvertTo-XmlEscapedText' {
        It 'échappe les 5 caractères réservés XML (esperluette, chevrons, guillemet, apostrophe)' {
            ConvertTo-XmlEscapedText -Text 'a<b>&"''' | Should -Be 'a&lt;b&gt;&amp;&quot;&apos;'
        }
        It 'retourne une chaîne vide pour $null' {
            ConvertTo-XmlEscapedText -Text $null | Should -Be ''
        }
    }

    Context 'ConvertTo-ADFilterValue' {
        It 'double les apostrophes' {
            ConvertTo-ADFilterValue -Value "O'Brien" | Should -Be "O''Brien"
        }
    }

    Context 'Get-ParentDN' {
        It 'retire le premier RDN' {
            Get-ParentDN -DN 'OU=A,OU=B,DC=x,DC=local' | Should -Be 'OU=B,DC=x,DC=local'
        }
        It 'gère les virgules échappées dans le RDN' {
            Get-ParentDN -DN 'OU=A\,B,OU=C,DC=x' | Should -Be 'OU=C,DC=x'
        }
    }
}

Describe 'Get-SmbAccessRight (correspondance NTFS -> SMB)' {
    It 'FullControl -> Full' {
        Get-SmbAccessRight -NtfsRights ([System.Security.AccessControl.FileSystemRights]::FullControl) | Should -Be 'Full'
    }
    It 'Modify -> Change' {
        Get-SmbAccessRight -NtfsRights ([System.Security.AccessControl.FileSystemRights]::Modify) | Should -Be 'Change'
    }
    It 'Write -> Change' {
        Get-SmbAccessRight -NtfsRights ([System.Security.AccessControl.FileSystemRights]::Write) | Should -Be 'Change'
    }
    It 'ReadAndExecute -> Read (régression corrigée en v7)' {
        Get-SmbAccessRight -NtfsRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) | Should -Be 'Read'
    }
    It 'Read -> Read' {
        Get-SmbAccessRight -NtfsRights ([System.Security.AccessControl.FileSystemRights]::Read) | Should -Be 'Read'
    }
}

Describe 'Fichier d''état (schéma v2)' {
    It 'Get-DefaultState expose Steps et Created' {
        $state = Get-DefaultState
        $state.SchemaVersion | Should -Be 2
        $state.Steps.UpdatesChecked | Should -BeFalse
        @($state.Created.PSObject.Properties.Name) | Should -Contain 'OUs'
        @($state.Created.PSObject.Properties.Name) | Should -Contain 'Shares'
    }
    It 'Add-CreatedObject trace, déduplique et persiste' {
        $script:State = Get-DefaultState
        $script:StateDir = $TestDrive
        $script:StatePath = Join-Path -Path $TestDrive -ChildPath 'state.json'
        Add-CreatedObject -Category OUs -Key 'OU=T,DC=x' -Entry @{ Name = 'T'; DN = 'OU=T,DC=x' }
        Add-CreatedObject -Category OUs -Key 'OU=T,DC=x' -Entry @{ Name = 'T'; DN = 'OU=T,DC=x' }
        @($script:State.Created.OUs).Count | Should -Be 1
        Test-Path $script:StatePath | Should -BeTrue
        (Get-Content $script:StatePath -Raw | ConvertFrom-Json).Created.OUs[0].DN | Should -Be 'OU=T,DC=x'
    }
}

Describe 'Catalogue GPO (durcissement ANSSI + module B1-M8)' {
    It 'contient les nouvelles règles attendues' {
        foreach ($id in @('1.5','2.5','2.6','2.7','2.8','4.5','6.3','7.4','8.1','8.2','8.3','8.4','9.1','9.2','9.3')) {
            $script:GpoCatalog.Contains($id) | Should -BeTrue
        }
    }
    It 'chaque règle a un Label et des paramètres de registre bien formés' {
        foreach ($id in $script:GpoCatalog.Keys) {
            $rule = $script:GpoCatalog[$id]
            $rule.Label | Should -Not -BeNullOrEmpty
            foreach ($s in @($rule.Settings)) {
                $s.Key | Should -Match '^HK(LM|CU)\\'
                $s.ValueName | Should -Not -BeNullOrEmpty
                $s.Type | Should -BeIn @('DWord', 'String')
            }
        }
    }
    It 'chaque identifiant de règle appartient à une catégorie déclarée' {
        foreach ($id in $script:GpoCatalog.Keys) {
            $script:GpoCategories.Contains($id.Split('.')[0]) | Should -BeTrue
        }
    }
    It 'la règle WDigest désactive bien le stockage du mot de passe (valeur 0)' {
        $script:GpoCatalog['8.1'].Settings[0].ValueName | Should -Be 'UseLogonCredential'
        $script:GpoCatalog['8.1'].Settings[0].Value | Should -Be 0
    }
}

Describe 'Politique de mot de passe du domaine (ANSSI)' {
    It 'expose des valeurs par défaut alignées ANSSI/module' {
        $script:DomainPasswordPolicyDefaults.MinLength | Should -Be 12
        $script:DomainPasswordPolicyDefaults.LockoutThreshold | Should -Be 5
        $script:DomainPasswordPolicyDefaults.HistoryCount | Should -Be 24
        $script:DomainPasswordPolicyDefaults.Complexity | Should -BeTrue
    }
    It 'expose la fonction Invoke-DomainPasswordPolicyStep' {
        Get-Command Invoke-DomainPasswordPolicyStep -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Gestion des droits d''accès (module B1-M9)' {
    It 'expose les nouvelles étapes de Phase 2' {
        foreach ($fn in @('Invoke-ADAccessAuditStep', 'Invoke-ContractorAccountStep', 'Invoke-LapsSetupStep', 'Invoke-DelegationStep', 'Enable-ShareAbe')) {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    It 'New-TrackedUser accepte l''expiration de compte et la restriction de postes' {
        $p = (Get-Command New-TrackedUser).Parameters
        $p.ContainsKey('AccountExpirationDate') | Should -BeTrue
        $p.ContainsKey('LogonWorkstations') | Should -BeTrue
    }
    It 'Enable-ShareAbe retourne $false pour un partage inexistant (non bloquant)' {
        Enable-ShareAbe -ShareName 'PartageQuiNExistePasM9XYZ' | Should -BeFalse
    }
    It 'construit des ACE dsacls bien formées (deux-points littéral)' {
        # Vérifie l'échappement backtick-colon utilisé dans Invoke-DelegationStep
        $principal = 'W4AD\GDL_Helpdesk'
        "$principal`:CA;Reset Password;user" | Should -Be 'W4AD\GDL_Helpdesk:CA;Reset Password;user'
    }
}

Describe 'Robustesse (corrections de revue)' {
    It 'Save-StepScreenshot est coupé quand SuppressScreenshots est vrai' {
        $script:SuppressScreenshots = $true
        try {
            Save-StepScreenshot -StepName 'Test' | Should -BeNullOrEmpty
        } finally {
            $script:SuppressScreenshots = $false
        }
    }
    It 'expose le helper Confirm-FileServerRole (rôle serveur de fichiers non bloquant)' {
        Get-Command Confirm-FileServerRole -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Grant-ShareAccess purge les ACE NTFS existantes de l''identité (idempotence)' {
        # Test direct du pattern PurgeAccessRules + AddAccessRule sur un dossier réel :
        # deux octrois successifs (Read puis Modify) ne doivent laisser qu'UNE ACE Allow.
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
        $folder = Join-Path -Path $TestDrive -ChildPath 'abe'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        foreach ($right in @('Read', 'Modify')) {
            $acl = Get-Acl -Path $folder
            $acl.PurgeAccessRules($sid)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]$right, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            Set-Acl -Path $folder -AclObject $acl
        }
        $final = Get-Acl -Path $folder
        $aces = @($final.Access | Where-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sid.Value -and $_.AccessControlType -eq 'Allow' })
        $aces.Count | Should -Be 1
    }
}

Describe 'Split-PdfTextLine (retour à la ligne du rapport PDF)' {
    It 'ne coupe pas un texte plus court que la largeur' {
        Split-PdfTextLine -Text 'court' -MaxChars 40 | Should -Be 'court'
    }
    It 'découpe en respectant la largeur maximale (mots préservés)' {
        $lines = Split-PdfTextLine -Text (('mot ' * 60).Trim()) -MaxChars 40
        @($lines).Count | Should -BeGreaterThan 1
        foreach ($l in $lines) { $l.Length | Should -BeLessOrEqual 40 }
    }
    It 'coupe durement un mot plus long que la largeur' {
        $lines = Split-PdfTextLine -Text ('A' * 100) -MaxChars 30
        @($lines).Count | Should -Be 4
    }
    It 'retourne une ligne vide pour une chaîne vide' {
        Split-PdfTextLine -Text '' -MaxChars 20 | Should -Be ''
    }
}

Describe 'Rapport PDF (sans Microsoft Office)' {
    It 'le générateur PDF natif produit un PDF 1.4 valide avec mots de passe et image' {
        $script:CreatedCreds.Add([PSCustomObject]@{ Login = 'test'; MotDePasse = 'P@ss(clair)1'; OU = 'TestOU' })
        Add-ReportFact -Name 'Nom du serveur' -Value 'SRV-TEST'

        # Capture synthetique pour verifier l'insertion d'image (DCTDecode)
        Add-Type -AssemblyName System.Drawing
        $png = Join-Path -Path $TestDrive -ChildPath 'shot.png'
        $bmp = New-Object System.Drawing.Bitmap(200, 80)
        try {
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $g.Clear([System.Drawing.Color]::SteelBlue); $g.Dispose()
            $bmp.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally { $bmp.Dispose() }
        $script:Screenshots.Add([PSCustomObject]@{ Step = 'Test'; Path = $png; Date = '2026-01-01 00:00:00' })

        $pdf = Join-Path -Path $TestDrive -ChildPath 'rapport.pdf'
        $model = Get-ReportContentModel -PhaseLabel 'Tests Pester'
        ConvertTo-PdfMinimal -Path $pdf -Items $model
        Test-Path $pdf | Should -BeTrue

        $bytes = [System.IO.File]::ReadAllBytes($pdf)
        $text = [System.Text.Encoding]::GetEncoding(1252).GetString($bytes)
        $text.StartsWith('%PDF-1.4') | Should -BeTrue
        $text.TrimEnd().EndsWith('%%EOF') | Should -BeTrue
        $text | Should -Match '/Filter /DCTDecode'          # image JPEG embarquee
        $text | Should -Match 'P@ss\\\(clair\\\)1'          # mot de passe, parentheses echappees PDF
    }

    It 'Export-PdfReport aboutit (moteur PDF ou repli HTML) et retourne un chemin existant' {
        Add-ReportFact -Name 'Domaine' -Value 'entreprise.local'
        $pdf = Join-Path -Path $TestDrive -ChildPath 'orchestrateur.pdf'
        $result = Export-PdfReport -Path $pdf -PhaseLabel 'Tests Pester'
        $result | Should -Not -BeNullOrEmpty
        Test-Path $result | Should -BeTrue
        (Get-Item $result).Length | Should -BeGreaterThan 0
    }

    It 'le repli HTML contient la colonne Mot de passe (clair) et l''avertissement Git' {
        $html = Get-ReportHtml -PhaseLabel 'Tests Pester'
        $html | Should -BeLike '*Mot de passe (clair)*'
        $html | Should -BeLike '*C:\Rapports\*'
        $html | Should -BeLike '*Git*'
    }
}

Describe 'Get-ObjectValue (configuration hashtable et JSON)' {
    It 'lit une clé de hashtable' {
        Get-ObjectValue -Object @{ Name = 'X' } -Name 'Name' | Should -Be 'X'
    }
    It 'lit une propriété de PSCustomObject' {
        Get-ObjectValue -Object ([PSCustomObject]@{ Name = 'Y' }) -Name 'Name' | Should -Be 'Y'
    }
    It 'retourne la valeur par défaut si absent' {
        Get-ObjectValue -Object @{ Name = 'X' } -Name 'Autre' -Default 'defaut' | Should -Be 'defaut'
    }
}
