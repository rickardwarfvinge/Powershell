Function Set-ADDelegation () {

<#
    .SYNOPSIS
    Delegate control for identities in Active Directory with predefined delegation packets.
    
    .DESCRIPTION
    Delegate control for user, group or computer. Choose between predefined delegation packages. Optional console output (ON/OFF, default: ON)
    Name convention check for groups (override possible, default: ON).
    Helper functions used:

    New-ADDGuidMap: Function to create and return a hashtable of Active Directory attribute names to their corresponding schema GUIDs
    New-ADDExtendedRightMap: Function to create and return a hashtable of Active Directory extended rights to their corresponding GUIDs.
    Show-ADACLUpdateSummary: Function to display console information after updating an Active Directory ACL
        
    Detailed description of delegation packets:
        
    Delegation 'ComputerDomainJoin'
        Type: Allow
        Access: Reset password, Validated write to DNS host name, Validated write to service principal name, Read/Write account restrictions
        Applies to: Descendants Computer Objects
        
    Delegation 'ComputerCreateDelete'
        Type: Allow
        Access: Create/delete computer objects
        Applies to: This object and all descendants Objects

    Delegation 'ComputerCreate'
        Type: Allow
        Access: Create computer objects
        Applies to: This object and all descendants Objects

    Delegation 'ComputerDelete'
        Type: Allow
        Access: Delete computer objects
        Applies to: This object and all descendants Objects
            
    Delegation 'ComputerDisable'
        Type: Allow
        Access: Disable computer objects
        Applies to: This object and all descendants Objects

    Delegation 'ComputerReadWrite'
        Type: Allow
        Access: Read/Write computer objects
        Applies to: Descendants Computer Objects

    Delegation 'GPOLink'
        Type: Allow
        Access: Read/Write gPLink and gPOptions
        Applies to: This object and all descendants Objects
        
    Delegation 'GPOGenerateRSOP'
        Type: Allow
        Access: Generate resultant set of policy (planning/logging)
        Applies to: This object and all descendants Objects

    Delegation 'GroupCreateDelete'
        Type: Allow
        Access: Create/delete Group Objects
        Applies to: Descendants Group Objects

    Delegation 'GroupCreate'
        Type: Allow
        Access: Create Group Objects
        Applies to: Descendants Group Objects

    Delegation 'GroupDelete'
        Type: Allow
        Access: Delete Group Objects
        Applies to: Descendants Group Objects

    Delegation 'GroupWriteMember'
        Type: Allow
        Access: Read/Write Group Members
        Applies to: Descendants Group Objects

    Delegation 'GroupWriteExtAttr1'
        Type: Allow
        Access: Read/Write extensionAttribute1
        Applies to: Descendants Group Objects

    Delegation 'GroupWriteExtAttr7'
        Type: Allow
        Access: Read/Write extensionAttribute7
        Applies to: Descendants Group Objects

    .EXAMPLE 
    PS> Set-ADDelegation -IdentityToDelegateTo ADGroup01 -OuDistinguishedName "OU=computers,OU=test,DC=domain,DC=com" -DelegationPackage 'GPOGenerateRSOP'
        
    This example creates a Group Policy RSOP (Planning/Logging) delegation for identity 'ADGroup01' on OU: 'OU=computers,OU=test,DC=domain,DC=com' with console output

    .EXAMPLE 
    PS> Set-ADDelegation -IdentityToDelegateTo ADGroup01 -OuDistinguishedName "OU=computers,OU=test,DC=domain,DC=com" -DelegationPackage 'GroupDelete' -ConsoleOutput OFF
        
    This example creates delete delegation of group objects for identity 'ADGroup01' on OU: 'OU=computers,OU=test,DC=domain,DC=com' without console output

    .EXAMPLE 
    PS> Set-ADDelegation -IdentityToDelegateTo ADGroup01 -OuDistinguishedName "OU=computers,OU=test,DC=domain,DC=com" -DelegationPackage 'GroupWriteExtAttr1' -NamingConventionCheck ON
        
    This example creates read/write delegation of extensionAttribute1 for identity 'ADGroup01' on OU: 'OU=computers,OU=test,DC=domain,DC=com' with override enabled for group naming check
        
    Console output with ACL update summary (optional)
        
    .PARAMETER IdentityToDelegateTo
    Active Directory identity to delegate to. Allowed object types: User,Group or Computer
    
    .PARAMETER OuDistinguishedName
    DistinguishedName of OrganizationalUnit where the delegation will take place
        
    .PARAMETER DelegationPackage
    Name of the predefined delegation packet

    .PARAMETER NamingConventionCheck
    Naming convention check for group objects, ON or OFF (Default: ON)
        
    .PARAMETER ConsoleOutput
    Console output, ON or OFF (Default: ON)
    
    .NOTES
        Requirements:
            Powershell Module: ActiveDirectory
            
        Future Improvements:
            Add logic when an ACL is reused (Eg. ComputerDelete is already set and ComputerCreateDelete is added and the same ACL is only updated) causing
            the functions console output to display a warning that no ACL is applied even tough it is applied.
            The logic behind the console output should be dynamically in the ACL BLOCK. Some parts are, but not all.
                
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
                'ComputerCreateDelete',
                'ComputerCreate',
                'ComputerDelete',
                'ComputerDisable',
                'ComputerReadWrite',
                'GPOLink',
                'GPOGenerateRSOP',
                'GroupCreateDelete',
                'GroupCreate',
                'GroupDelete',
                'GroupWriteMember',
                'GroupWriteExtAttr1',
                'GroupWriteExtAttr7'
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

# Function to create and return a hashtable of Active Directory attribute names to their corresponding schema GUIDs
Function New-ADDGuidMap {
    $rootdse = Get-ADRootDSE
    $guidmap = @{ }
    $GuidMapParams = @{
        SearchBase = ($rootdse.SchemaNamingContext)
        LDAPFilter = "(schemaidguid=*)"
        Properties = ("lDAPDisplayName", "schemaIDGUID")
    }
    Get-ADObject @GuidMapParams | ForEach-Object { $guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }
    return $guidmap
}

# Function to create and return a hashtable of Active Directory extended rights to their corresponding GUIDs. 
Function New-ADDExtendedRightMap {
    $rootdse = Get-ADRootDSE
    $ExtendedMapParams = @{
        SearchBase = ($rootdse.ConfigurationNamingContext)
        LDAPFilter = "(&(objectclass=controlAccessRight)(rightsguid=*))"
        Properties = ("displayName", "rightsGuid")
    }
    $extendedrightsmap = @{ }
    Get-ADObject @ExtendedMapParams | ForEach-Object { $extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid }
    return $extendedrightsmap
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

    Write-Host "`n================ ACL UPDATE SUMMARY ==================" -ForegroundColor Cyan
    Write-Host "Permission Set Successfully!" -ForegroundColor Green
    Write-Host "- Target OU: $OuDistinguishedName"
    Write-Host "- Type: $Type"
    Write-Host "- Delegated To: $DelegatedTo"
    Write-Host "- Access: $Access"
    Write-Host "- Applies To: $AppliesTo"
    Write-Host "======================================================`n" -ForegroundColor Cyan
}

$GuidMap = New-ADDGuidMap
$ExtendedRight = New-ADDExtendedRightMap
$ADObject = Get-ADObject -Filter "Name -eq '$IdentityToDelegateTo'"

If ($NamingConventionCheck -eq 'ON') {
    # Verify correct naming convention
    If ($ADObject.ObjectClass -eq 'Group') {
        If (-Not($IdentityToDelegateTo -like "*$DelegationPackage")) {
            Throw "Active Directory Group: '$($ADObject.Name)' is incorrectly named. The group name must end with the selection you made in DelegationDetails: '$DelegationPackage'."
        }
    }
}

# Retrieve object SID (User, Computer, or Group)
Switch ((Get-ADObject -Filter "Name -eq '$IdentityToDelegateTo'").ObjectClass) {
    
    'User' {
        $IdentitySID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADUser $IdentityToDelegateTo).SID
    }
    
    'Group' {
        $IdentitySID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $IdentityToDelegateTo).SID
    }
    
    'Computer' {
        $IdentitySID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADComputer $IdentityToDelegateTo).SID
    }
}

Switch ($DelegationPackage) {
                
    'ComputerDomainJoin' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ExtendedRight","Allow",$ExtendedRight["Reset Password"],"Descendents",$GuidMap["Computer"]))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"Self","Allow",$ExtendedRight["Validated write to DNS host name"],"Descendents",$GuidMap["Computer"]))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"Self","Allow",$ExtendedRight["Validated write to service principal name"],"Descendents",$GuidMap["Computer"]))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$ExtendedRight["Account restrictions"], "Descendents",$GuidMap["Computer"]))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "Descendent computer objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'ComputerCreateDelete' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild,DeleteChild","Allow",$GuidMap["Computer"],"All"))
    
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                $Access = "Create/delete computer objects ($($Rule.ActiveDirectoryRights))"
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This object and all descendent objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }           
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'ComputerCreate' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild","Allow",$GuidMap["Computer"],"All"))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                $Access = "Create computer objects ($($Rule.ActiveDirectoryRights))"
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This object and all descendent objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'ComputerDelete' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"DeleteChild","Allow",$GuidMap["Computer"],"All"))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                $Access = "Delete computer objects ($($Rule.ActiveDirectoryRights))"
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This object and all descendent objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'ComputerDisable' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["UserAccountControl"], "Descendents",$GuidMap["Computer"]))
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                $Access = "Disable computer objects ($($Rule.ActiveDirectoryRights))"
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "Descendent computer objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'ComputerReadWrite' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty,WriteProperty","Allow",$([GUID]::Empty).Guid,"Descendents",$GuidMap["Computer"]))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                $Access = "Read/Write all properties ($($Rule.ActiveDirectoryRights))"
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "Descendent computer objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'GPOLink' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID, "ReadProperty,WriteProperty","Allow",$GuidMap["GPLink"],"All"))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID, "ReadProperty,WriteProperty","Allow",$GuidMap["GPOptions"],"All"))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "gPLink/gPOptions ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This object and all descendent objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'GPOGenerateRSOP' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ExtendedRight","Allow",$ExtendedRight["Generate Resultant Set of Policy (Planning)"],"All"))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ExtendedRight","Allow",$ExtendedRight["Generate Resultant Set of Policy (Logging)"],"All"))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "$(($GuidMap.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This object and all descendent objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'GroupWriteMember' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty","Allow",$GuidMap["member"],"Descendents",$GuidMap["Group"]))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["member"],"Descendents",$GuidMap["Group"]))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "Group members ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "Descendants Group Objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'GroupCreateDelete' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild,DeleteChild","Allow",$GuidMap["Group"],"All"))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "Group ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This Object And All Descendants Objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                } 
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'GroupCreate' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"CreateChild","Allow",$GuidMap["Group"],"All"))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "Group ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This Object And All Descendants Objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                } 
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK 

    'GroupDelete' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"DeleteChild","Allow",$GuidMap["Group"],"All"))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "Group ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "This Object And All Descendants Objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK 
        
    'GroupWriteExtAttr1' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty","Allow",$GuidMap["extensionAttribute1"],"Descendents",$GuidMap["Group"]))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["extensionAttribute1"],"Descendents",$GuidMap["Group"]))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "$(($GuidMap.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "Descendants Group Objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

    'GroupWriteExtAttr7' {
        
        # ACL BLOCK
        $Acl = Get-Acl -Path "AD:\$OuDistinguishedName" # Retrive ACL(s) from OrganizationalUnit
        $PreviousAcl = New-Object System.DirectoryServices.ActiveDirectorySecurity # Create new object for storing current ACL(s)
        $Acl.Access | ForEach-Object {$PreviousAcl.AddAccessRule($_)}

        # Add access rules and set new ACLs
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"ReadProperty","Allow",$GuidMap["extensionAttribute7"],"Descendents",$GuidMap["Group"]))
        $Acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentitySID,"WriteProperty","Allow",$GuidMap["extensionAttribute7"],"Descendents",$GuidMap["Group"]))
        
        Try {
            Set-Acl -Path "AD:\$OuDistinguishedName" -AclObject $Acl -ErrorAction Stop # Set ACL(s)
            # Filtering out only new ACLs for the selected principal. Used for output
            $AppliedRules = Compare-Object -ReferenceObject $PreviousAcl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) -DifferenceObject $Acl.Access.Where({$_.IdentityReference -eq "$env:USERDOMAIN\$IdentityToDelegateTo"}) | Select-Object -ExpandProperty InputObject
            If ($Null -eq $AppliedRules) {
                Write-Warning "No new ACL changes applied. The requested delegation ($DelegationPackage) is already granted through a broader existing delegation."
            }

            Else {
                Foreach ($Rule in $AppliedRules) {
                If ($Rule.ActiveDirectoryRights -eq 'ExtendedRight') { # ExtendedRight GUID
                    $Access = "$(($ExtendedRight.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                Else { # GUID Map
                    $Access = "$(($GuidMap.GetEnumerator() | Where-Object Value -eq $Rule.ObjectType).Key) ($($Rule.ActiveDirectoryRights))"
                }
                $Type = $Rule.AccessControlType
                $DelegatedTo = $IdentityToDelegateTo
                $AppliesTo = "Descendants Group Objects"
                If ($ConsoleOutput -eq 'ON') { # Output info to console
                    Show-ADACLUpdateSummary -OuDistinguishedName $OuDistinguishedName -Type $Type -DelegatedTo $DelegatedTo -Access $Access -AppliesTo $AppliesTo
                }
                }
            }
        }

        Catch {Throw $error[0]}
    } # END ACL BLOCK

}
}
