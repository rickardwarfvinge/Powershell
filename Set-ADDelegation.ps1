Function Set-ADDelegation () {

    <#

    .SYNOPSIS
    Delegate control for identities in Active Directory with predefined delegation packages.

    .DESCRIPTION
    Delegate control for user, group, or computer. Choose from predefined delegation packages. Optional console output (default: ON)
    If you want to add new DelegationPackages just add the appropriate AccessRule(s) and create a new block in the switch clause
    Optional: Naming convention check for group identities: the AD group name must end with the same name as the delegation package
    Example: DelegationPackage 'GroupCreate' must map to group 'GroupName-GroupCreate' (default: OFF)

    Sub functions used:
    - New-ADDGuidMap: returns a hashtable allowing both name-to-GUID and GUID-to-name lookups
    - New-ADDExtendedRightMap: returns a hashtable of extended rights with both directions
    - Get-ADObjectPermissions: retrieves and resolves the DACL for an AD object
    - Get-ADObjectAddedPermissions: compares two permission sets to find newly added ACEs
    - Invoke-ACLBlock: applies access rules and outputs only newly added permissions
    - Show-ADACLUpdateSummary: displays console output after ACL changes

    .EXAMPLE
    Set-ADDelegation -IdentityToDelegateTo ADGroup01 -OuDistinguishedName "OU=computers,OU=test,DC=domain,DC=com" -DelegationPackage 'GPOGenerateRSOP'

    .EXAMPLE
    Set-ADDelegation -IdentityToDelegateTo ADGroup01 -OuDistinguishedName "OU=computers,OU=test,DC=domain,DC=com" -DelegationPackage 'GroupDelete' -ConsoleOutput OFF

    .EXAMPLE
    Set-ADDelegation -IdentityToDelegateTo ADGroup01 -OuDistinguishedName "OU=computers,OU=test,DC=domain,DC=com" -DelegationPackage 'GroupWriteExtAttr1' -NamingConventionCheck ON

    .PARAMETER IdentityToDelegateTo
    Active Directory identity to delegate to. Allowed types: User, Group, or Computer

    .PARAMETER OuDistinguishedName
    DistinguishedName of the OrganizationalUnit

    .PARAMETER DelegationPackage
    Name of the predefined delegation packet

    .PARAMETER NamingConventionCheck
    Check for naming convention (default: ON)

    .PARAMETER ConsoleOutput
    Enable or disable console output (default: ON)

    .NOTES
        Requires: PowerShell ActiveDirectory module
        Author: Rickard Warfvinge
        
    #>

[CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true,
        HelpMessage = "Input Active Directory identity to delegate to.")]
        [ValidateScript(
            {If (Get-ADObject -Filter "Name -eq '$_'" | Where-Object {$_.ObjectClass -eq 'Computer' -or $_.ObjectClass -eq 'User' -or $_.ObjectClass -eq 'Group'}) {
                $true
            }
            Else {
            Throw "Principal '$_' cannot be found in Active Directory or is an disallowed object type."
            }
        }
        )]
        [String]$IdentityToDelegateTo,

        [Parameter(Position = 1, Mandatory = $true,
        HelpMessage = "Enter DistinguishedName to organizational unit (OU).")]
        [ValidateScript(
            {If (Get-ADObject -Filter "distinguishedName -eq '$_'" | Where-Object {$_.ObjectClass -eq 'organizationalUnit'}) {
                $true
            }
            Else {
            Throw "DistinguishedName of organizationalUnit: '$_' cannot be found in Active Directory."
            }
        }
        )]
        [String]$OuDistinguishedName,

        [Parameter(Position = 2, Mandatory = $true,
        HelpMessage = "Choose between predefined delegation packets.")]
        [ValidateSet(
            'ComputerDomainJoin',
            'ComputerFullControl',
            'ComputerCreateDelete',
            'ComputerCreate',
            'ComputerDelete',
            'ComputerWriteUserAccountControl',
            'ComputerDeleteMove',
            'ComputerReadWrite',
            'ComputerResetPassword',
            'ComputerWriteDescriptionAndComment',
            'ComputerModifyPermissions',
            'ComputerBitLockerRecoveryInfo',
            'GPOLink',
            'GPOGenerateRSOP',
            'GroupCreateDelete',
            'GroupCreate',
            'GroupDelete',
            'GroupWriteMembers',
            'GroupWriteExtAttr1',
            'GroupWriteExtAttr7',
            'UserWriteExtAttr6',
            'UserWriteAltSecurityIdentities'
            )]
        [String]$DelegationPackage,

        [Parameter(Position = 3, Mandatory=$false,
        HelpMessage = "Disable group naming convention check")]
        [ValidateSet('ON','OFF')]
        [String]$NamingConventionCheck = 'ON',

        [Parameter(Position = 4, Mandatory=$false,
        HelpMessage = "Turn console output ON, or OFF")]
        [ValidateSet('ON','OFF')]
        [String]$ConsoleOutput = 'ON'
    )

# Function that returns a hashtable allowing both name -> GUID and GUID -> name lookups
Function New-ADDGuidMap {
    $RootDse = Get-ADRootDSE
    $GuidMap = @{}

    $Params = @{
        SearchBase = $RootDse.SchemaNamingContext
        LDAPFilter = "(schemaidguid=*)"
        Properties = @("lDAPDisplayName", "schemaIDGUID")
    }

    Get-ADObject @Params | ForEach-Object {
        $Name = $_.lDAPDisplayName
        $Guid = [System.GUID]$_.schemaIDGUID
        $GuidStr = $Guid.Guid.ToLower()

        $Guidmap[$Name] = $Guid
        $Guidmap[$GuidStr] = $Name
    }

    Return $GuidMap
}

# Function that returns a hashtable of extended rights with both displayName -> GUID and GUID -> displayName
Function New-ADDExtendedRightMap {
    $RootDse = Get-ADRootDSE
    $ExtendedRightsMap = @{}

    $Params = @{
        SearchBase = $RootDse.ConfigurationNamingContext
        LDAPFilter = "(&(objectclass=controlAccessRight)(rightsguid=*))"
        Properties = @("displayName", "rightsGuid")
    }

    Get-ADObject @Params | ForEach-Object {
        $Name = $_.displayName
        $Guid = [System.GUID]$_.rightsGuid
        $GuidStr = $Guid.Guid.ToLower()

        $ExtendedRightsMap[$Name] = $Guid
        $ExtendedRightsMap[$GuidStr] = $Name
    }

    Return $ExtendedRightsMap
}

# Function that retrieves and resolves the DACL for an Active Directory object
Function Get-ADObjectPermissions {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory, Position=0)]
        [string]$DistinguishedName,

        [Parameter(Position=1)]
        [string]$Identity
    )

    If ($Identity -and ($Identity -notmatch '^[^\\]+\\[^\\]+$')) {
        $Identity = "$env:USERDOMAIN\$Identity"
    }

    # Build mapping of GUIDs to names from schema and extended rights
    $RootDse = Get-ADRootDSE
    $SchemaNC = $RootDse.SchemaNamingContext
    $ConfigNC = $RootDse.ConfigurationNamingContext

    $GuidToName = @{}

    # Map schemaIDGUID (attributes and classes)
    Get-ADObject -SearchBase $SchemaNC -LDAPFilter "(schemaIDGUID=*)" -Properties lDAPDisplayName, schemaIDGUID | ForEach-Object {
        If ($_.schemaIDGUID -and $_.lDAPDisplayName) {
            Try {
                $Guid = New-Object Guid (,$_.schemaIDGUID)
                $GuidToName[$Guid.Guid.ToString().ToLower()] = $_.lDAPDisplayName
            } catch { }
        }
    }

    # Map extended rights (controlAccessRight)
    Get-ADObject -SearchBase $ConfigNC -LDAPFilter "(&(objectClass=controlAccessRight)(rightsGuid=*))" -Properties displayName, rightsGuid | ForEach-Object {
        if ($_.rightsGuid -and $_.displayName) {
            try {
                $Guid = [Guid]$_.rightsGuid
                $GuidToName[$Guid.ToString().ToLower()] = $_.displayName
            } catch { }
        }
    }

    # Get ACL from the AD object
    $Acl = Get-Acl -Path "AD:\$DistinguishedName"

    # Filter ACEs by identity if provided
    $FilteredAccess = If ($Identity) {
        $Acl.Access | Where-Object { $_.IdentityReference -eq $Identity }
    } Else {
        $Acl.Access
    }

    # Parse and format each ACE
    $Results = foreach ($Ace in $FilteredAccess) {
        $InheritedFrom = if ($Ace.IsInherited) { "Inherited" } else { "Explicit" }

        # Resolve AppliesTo
        $AppliesTo = switch ($Ace.InheritanceType) {
            "None" { "This object only" }
            "All" { "This object and all descendant objects" }
            "Descendents" {
                If ($Ace.InheritedObjectType -ne [Guid]::Empty) {
                    $GuidRaw = $Ace.InheritedObjectType.Guid.ToString().ToLower()
                    If ($GuidToName.ContainsKey($GuidRaw)) {
                        "Descendant $($GuidToName[$GuidRaw]) objects"
                    } Else {
                        "Descendant $guidRaw objects"
                    }
                } Else {
                    "All descendant objects"
                }
            }
            Default { $Ace.InheritanceType }
        }

        # Build access string with detail
        $AccessString = $Ace.ActiveDirectoryRights.ToString()
        If ($Ace.ObjectType -ne [Guid]::Empty) {
            $ObjectGuid = $Ace.ObjectType.Guid.ToString().ToLower()
            If ($GuidToName.ContainsKey($ObjectGuid)) {
                $AccessString += " ($($GuidToName[$ObjectGuid]))"
            } Else {
                $AccessString += " $ObjectGuid"
            }
        }

        [PSCustomObject]@{
            Type          = $Ace.AccessControlType
            Principal     = $Ace.IdentityReference.ToString()
            Access        = $AccessString
            InheritedFrom = $InheritedFrom
            AppliesTo     = $AppliesTo
        }
    }

    Return $Results
}

# Function that identifies newly added access control entries by comparing two permission sets
Function Get-ADObjectAddedPermissions {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [array]$Before,

        [Parameter(Mandatory = $true)]
        [array]$After,

        [switch]$SilentIfNone  # Optional flag to suppress output if nothing new
    )

    $NewRules = foreach ($Entry in $After) {
        $Exists = $Before | Where-Object {
            $_.Type          -eq $Entry.Type          -and
            $_.Principal     -eq $Entry.Principal     -and
            $_.Access        -eq $Entry.Access        -and
            $_.AppliesTo     -eq $Entry.AppliesTo     -and
            $_.InheritedFrom -eq $Entry.InheritedFrom
        }
        If (-not $Exists) {
            $Entry
        }
    }

    If (-not $NewRules) {
        if (-not $SilentIfNone) {
            Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
        }
        Return @()
    }

    Return $NewRules
}

# Function that applies a set of Active Directory access rules to an OU and outputs only the newly added permissions
Function Invoke-ACLBlock {
    Param (
        [string]$OuDistinguishedName,
        [System.Security.Principal.SecurityIdentifier]$IdentitySID,
        [ScriptBlock]$AclActions,
        [string]$DelegationName
    )

    $PreRules = Get-ADObjectPermissions -DistinguishedName $OuDistinguishedName
    $Acl = Get-Acl -Path "AD:\$OuDistinguishedName"

    $AclActions.Invoke($Acl)

    Try {
        Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop
        $PostRules = Get-ADObjectPermissions -DistinguishedName $OuDistinguishedName
        $AddedRules = Get-ADObjectAddedPermissions -Before $PreRules -After $PostRules -SilentIfNone

        If (($AddedRules | Measure-Object).Count -gt 0) {
            foreach ($Rule in $AddedRules) {
                Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Rule.Type -DelegatedTo $Rule.Principal -Access $Rule.Access -AppliesTo $Rule.AppliesTo
            }
        } else {
            Write-Warning "No new ACL changes applied. The requested delegation ($DelegationName) is already granted."
        }
    }
    Catch {
        Throw $Error[0]
    }
}

# Function to display console information after updating an Active Directory ACL
Function Show-ADACLUpdateSummary {
    Param (
        [Parameter(Mandatory)]
        [string]$OuDistinguishedName,

        [Parameter(Mandatory)]
        [string]$Type,

        [Parameter(Mandatory)]
        [string]$DelegatedTo,

        [Parameter(Mandatory)]
        [string]$Access,

        [Parameter(Mandatory)]
        [string]$AppliesTo
    )

    If ($ConsoleOutput -eq 'ON') {
        Write-Host "`n================ ACL UPDATE SUMMARY ==================" -ForegroundColor Cyan
        Write-Host "Permission Set Successfully!" -ForegroundColor Green
        Write-Host "- Target OU: $OuDistinguishedName"
        Write-Host "- Type: $Type"
        Write-Host "- Delegated To: $DelegatedTo"
        Write-Host "- Access: $Access"
        Write-Host "- Applies To: $AppliesTo"
        Write-Host "======================================================`n" -ForegroundColor Cyan
    }
}

    $GuidMap = New-ADDGuidMap
    $ExtendedRight = New-ADDExtendedRightMap
    $ADObject = Get-ADObject -Filter "Name -eq '$IdentityToDelegateTo'"

    If ($NamingConventionCheck -eq 'ON') { # Verify correct naming convention
        If ($ADObject.ObjectClass -eq 'Group') {
            If (-Not($IdentityToDelegateTo -like "*$DelegationPackage")) {
                Throw "Active Directory Group: '$($ADObject.Name)' is incorrectly named. The group name must end with the selection you made in DelegationDetails: '$DelegationPackage'."
            }
        }
    }

    # Retrieve object SID (User, Computer, or Group)
    Switch ((Get-ADObject -Filter "Name -eq '$IdentityToDelegateTo'").ObjectClass) {
        'User' {$IdentitySID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser $IdentityToDelegateTo).SID}
        'Group' {$IdentitySID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $IdentityToDelegateTo).SID}
        'Computer' {$IdentitySID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADComputer $IdentityToDelegateTo).SID}
    }

    Switch ($DelegationPackage) {

        'ComputerDomainJoin' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ExtendedRight","Allow",$ExtendedRight["Reset Password"],"Descendents",$GuidMap["Computer"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"Self","Allow",$ExtendedRight["Validated write to DNS host name"],"Descendents",$GuidMap["Computer"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"Self","Allow",$ExtendedRight["Validated write to service principal name"],"Descendents",$GuidMap["Computer"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$ExtendedRight["Account restrictions"],"Descendents",$GuidMap["Computer"]))
            }
        }

        'ComputerFullControl' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"GenericAll","Allow","Descendents",$GuidMap["Computer"]))
            }
        }

        'ComputerCreateDelete' {

            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"Delete","Allow","Descendents", $GuidMap["Computer"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild","Allow",$GuidMap["Computer"],"All"))
            }
        }

        'ComputerCreate' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild","Allow",$GuidMap["Computer"],"All"))
            }
        }

        'ComputerDelete' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"Delete","Allow","Descendents", $GuidMap["Computer"]))
            }
        }

        'ComputerDeleteMove' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"Delete","Allow","Descendents", $GuidMap["Computer"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$GuidMap["name"],"Descendents",$GuidMap["Computer"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$GuidMap["cn"],"Descendents",$GuidMap["Computer"]))
            }
        }

        'ComputerWriteUserAccountControl' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["UserAccountControl"], "Descendents",$GuidMap["Computer"]))
            }
        }

        'ComputerReadWrite' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$([GUID]::Empty).Guid,"Descendents",$GuidMap["Computer"]))
            }
        }

        'ComputerWriteDescriptionAndComment' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["Description"],"Descendents",$GuidMap["Computer"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["Comment"],"Descendents",$GuidMap["Computer"]))
            }
        }

        'ComputerResetPassword' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ExtendedRight","Allow",$ExtendedRight["Reset Password"],"Descendents",$GuidMap["Computer"]))
            }
        }

        'ComputerModifyPermissions' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadControl,WriteDacl","Allow","Descendents", $GuidMap["Computer"]))
            }
        }

        'GPOLink' {
             Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID, "ReadProperty,WriteProperty","Allow",$GuidMap["GPLink"],"All"))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID, "ReadProperty,WriteProperty","Allow",$GuidMap["GPOptions"],"All"))
                }
        }

        'GPOGenerateRSOP' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ExtendedRight","Allow",$ExtendedRight["Generate Resultant Set of Policy (Planning)"],"All"))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ExtendedRight","Allow",$ExtendedRight["Generate Resultant Set of Policy (Logging)"],"All"))
                }
        }

        'GroupWriteMembers' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty","Allow",$GuidMap["member"],"Descendents",$GuidMap["Group"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["member"],"Descendents",$GuidMap["Group"]))
                }
        }

        'GroupCreateDelete' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild,DeleteChild","Allow",$GuidMap["Group"],"All"))
                }
        }

        'GroupCreate' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild","Allow",$GuidMap["Group"],"All"))
                }
        }

        'GroupDelete' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"DeleteChild","Allow",$GuidMap["Group"],"All"))
                }
        }

        'GroupWriteExtAttr1' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$GuidMap["extensionAttribute1"],"Descendents",$GuidMap["Group"]))
                }
        }

        'GroupWriteExtAttr7' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$GuidMap["extensionAttribute7"],"Descendents",$GuidMap["Group"]))
                }
        }

        'UserWriteExtAttr6' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$GuidMap["extensionAttribute6"],"Descendents",$GuidMap["User"]))
                }
        }

        'ComputerBitLockerRecoveryInfo' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,ExtendedRight","Allow",$GuidMap["msFVE-KeyPackage"],"Descendents",$GuidMap["msFVE-RecoveryInformation"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,ExtendedRight","Allow",$GuidMap["msFVE-RecoveryPassword"],"Descendents",$GuidMap["msFVE-RecoveryInformation"]))
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty","Allow",$GuidMap["msFVE-RecoveryInformation"],"Descendents",$GuidMap["msFVE-RecoveryInformation"]))
                }
        }

        'UserWriteAltSecurityIdentities' {
            Invoke-ACLBlock -OuDistinguishedName $OuDistinguishedName -IdentitySID $IdentitySID -DelegationName $DelegationPackage -AclActions {
                Param($Acl)
                $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$GuidMap["altSecurityIdentities"],"Descendents",$GuidMap["User"]))
                }
        }
    }
}