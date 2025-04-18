﻿Function New-Tier0Account () {

    <#
        .SYNOPSIS
        Create Tier0 user account
    
        .DESCRIPTION
        Create Tier0 user account in Tier0 user OU (s0, t0)
        Join Tier0 mandatory groups and Protected Users group
        Set a long random password (120 characters with complexity)
        Set AccountNotDelegated to $true
        Set SmartCardLogonRequired to $true/$false
        Change Primary group from default Domain Users to new primary group
        Helper functions used:

        - 'Add-UserToGroup': Adds the new user to required AD groups.
        - 'Write-ConditionalOutput': Controls output verbosity based on the -Quiet switch.
        
        .PARAMETER Suffix
        End suffix of account (s0, t0)
    
        .PARAMETER SamAccountName
        SamAccountName of new Tier0 account
        
        .PARAMETER FirstName
        FirstName of new Tier0 account
    
        .PARAMETER LastName
        LastName of new Tier0 account
    
        .PARAMETER Department
        Department of new Tier0 account
    
        .PARAMETER SmartCardRequired
        Enable or disable SmartCardRequired ($True/$False)
    
        .PARAMETER Quiet
        Toggle console output ON/OFF with -Quiet switch

        .PARAMETER Tier0AccountOU
        The Organizational Unit path where the Tier0 account will be created. This should be in the distinguished name (DN) format.
        Default: "OU=T0-Accounts,OU=Tier 0,$((Get-ADDomain).DistinguishedName)".

        .PARAMETER Tier0UserGroup
        The AD group to which the Tier0 account will be added for user permissions. If specifying a custom group, use the distinguished name (DN) format.
        Default: "CN=Tier0 Users,OU=T0-Groups,OU=Tier 0,$((Get-ADDomain).DistinguishedName)".

        .PARAMETER Tier0PrimaryGroup
        The primary Global group assigned to the Tier0 account. For custom groups, specify the distinguished name (DN). PrimaryGroupID attribute only accepts Global security groups
        Default: "CN=Tier 0 Primary Group,OU=T0-Groups,OU=Tier 0,$((Get-ADDomain).DistinguishedName)".

        .PARAMETER ProtectedUsersGroup
        AD group for Protected Users to which the Tier0 account will be added. Custom groups should be specified in DN format.
        Default: "CN=Protected Users,CN=Users,$((Get-ADDomain).DistinguishedName)".
        
        .EXAMPLE 
        PS> New-Tier0Account -Suffix t0 -SamAccountName User01t0 -FirstName John -LastName Doe -SmartCardRequired True
        
        Create tier0 account with suffix t0 and SmartCardRequired True (default groups and default OU is used)
            
        .EXAMPLE
        PS> New-Tier0Account -Suffix s0 -SamAccountName User01s0 -FirstName John -LastName Doe -SmartCardRequired False -Quiet
        
        Create tier 0 account with suffix s0, SmartCardRequired False and suppress console output (default groups and default OU is used)

        .EXAMPLE
        PS> New-Tier0Account -Suffix s0 -SamAccountName User01s0 -FirstName John -LastName Doe -SmartCardRequired True`
            -Tier0AccountOU "OU=CustomAccounts,OU=Tier0,DC=domain,DC=com" `
            -Tier0UserGroup "CN=Custom-Tier0-User-Group,OU=Groups,DC=domain,DC=com" `
            -Tier0PrimaryGroup "CN=Custom-Tier0-Primary-Group,OU=Groups,DC=domain,DC=com" `
            -ProtectedUsersGroup "CN=Custom-Protected-Users,OU=Groups,DC=domain,DC=com"

        This example creates a Tier0 account with suffix s0, SmartCardRequired True and customized group memberships and OU path.

        
        .NOTES
            Requirements:
                Powershell Module: ActiveDirectory
                Ensure that custom group names and OU paths are specified in distinguished name (DN) format if not using default groups and default OU.

            Author: Rickard Warfvinge
    #>
    
    [CmdletBinding()]
        Param(
            [Parameter(Position = 0, Mandatory = $true)]
            [ValidateSet('s0','t0')] 
            [String]$Suffix,    
        
            [Parameter(Position = 1, Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [ValidateLength(1,20)]
            [ValidateScript(
                {$SamAccountName = $_
                    If ($SamAccountName.EndsWith($Suffix)) {
                        If(Get-ADObject -Filter "Name -eq '$SamAccountName'") {
                        Throw "Tier0 user account '$SamAccountName' already exist in Active Directory."
                        }
                        Else {
                            $true
                        }
                    }
                    Else {
                        Throw "Tier0 user account '$SamAccountName' must have an end prefix of '$($Suffix)'."
                    }
                }
            )]
            [String]$SamAccountName,
    
            [Parameter(Position = 2, Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [String]$FirstName,
    
            [Parameter(Position = 3, Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [String]$LastName,
            
            [Parameter(Position = 4, Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [String]$Department,
    
            [Parameter(Mandatory=$true)]
            [ValidateSet('True','False')] 
            [String]$SmartCardRequired,
    
            [Parameter(Mandatory=$false,
            HelpMessage = "Toggle console write output ON/OFF using -Quiet switch.")]
            [Switch]$Quiet,
            
            [Parameter(Mandatory=$false,
            HelpMessage = "Default OrganizationalUnit for Tier0 accounts")]
            [ValidatePattern('^([a-zA-Z]+=[^,]+,)*[a-zA-Z]+=[^,]+$')]
            [ValidateScript({
                If (Get-ADObject -Filter "DistinguishedName -eq '$_'" | Select-Object -ExpandProperty DistinguishedName) {
                $True
                }
                Else {
                    Throw "'$_' has incorrect syntax or doesn't exist in Active Directory. Specify the OrganizationalUnit in distinguished name (DN) format"
                }
            }
            )]
            [String]$Tier0AccountOU = "OU=T0-Accounts,OU=Tier 0,$((Get-ADDomain).DistinguishedName)",

            [Parameter(Mandatory=$false,
            HelpMessage = "Default group for Tier0 accounts")]
            [ValidatePattern('^([a-zA-Z]+=[^,]+,)*[a-zA-Z]+=[^,]+$')]
            [ValidateScript({
                If (Get-ADObject -Filter "DistinguishedName -eq '$_'" | Select-Object -ExpandProperty DistinguishedName) {
                $True
                }
                Else {
                    Throw "'$_' has incorrect syntax or doesn't exist in Active Directory. Specify the group name in distinguished name (DN) format"
                }
            }
            )]
            [String]$Tier0UserGroup = "CN=Tier0 Users,OU=T0-Groups,OU=Tier 0,$((Get-ADDomain).DistinguishedName)",
            
            [Parameter(Mandatory=$false,
            HelpMessage = "Primary group for Tier0 accounts")]
            [ValidatePattern('^([a-zA-Z]+=[^,]+,)*[a-zA-Z]+=[^,]+$')]
            [ValidateScript({
                If (Get-ADObject -Filter "DistinguishedName -eq '$_'" | Select-Object -ExpandProperty DistinguishedName) {
                    If ((Get-ADGroup -Filter "DistinguishedName -eq '$_'").GroupScope -eq 'Global') {
                        $True    
                    }
                    Else {
                        Throw "'$_' is a local AD group. PrimaryGroupID attribute only accepts Global security groups."
                    }
                    
                }
                Else {
                    Throw "'$_' has incorrect syntax or doesn't exist in Active Directory. Specify the group name in distinguished name (DN) format"
                }
            }
            )]
            [String]$Tier0PrimaryGroup = "CN=Tier 0 Primary Group,OU=T0-Groups,OU=Tier 0,$((Get-ADDomain).DistinguishedName)",

            [Parameter(Mandatory=$false,
            HelpMessage = "Protected users group for Tier0 accounts")]
            [ValidatePattern('^([a-zA-Z]+=[^,]+,)*[a-zA-Z]+=[^,]+$')]
            [ValidateScript({
                If (Get-ADObject -Filter "DistinguishedName -eq '$_'" | Select-Object -ExpandProperty DistinguishedName) {
                $True
                }
                Else {
                    Throw "'$_' has incorrect syntax or doesn't exist in Active Directory. Specify the group name in distinguished name (DN) format"
                }
            }
            )]
            [String]$ProtectedUsersGroup = "CN=Protected Users,CN=Users,$((Get-ADDomain).DistinguishedName)"
            
            )
    
        # Helper function
        Function Write-ConditionalOutput {
        Param (
            [Parameter(Mandatory = $true)]
            [Object]$Message
        )
    
        If (-Not $Quiet) {
            If ($Message -is [hashtable]) {
                Foreach ($key in $Message.Keys) {
                    Write-Output "$($key): $($Message[$key])"
                }
            }
            Else {
                Write-Output $Message
            }
        }
        }
        
        Add-Type -AssemblyName 'System.Web' # Used for creating a random long password
    
        $UserDetails = @{
            GivenName               = $FirstName 
            Surname                 = $LastName
            Name                    = $SamAccountName
            Department              = $Department
            DisplayName             = "$FirstName $LastName"
            SamAccountName          = $SamAccountName
            UserPrincipalName       = $SamAccountName + '@' + (Get-ADDomain).dnsroot 
            Path                    = $Tier0AccountOU
            AccountPassword         = $(ConvertTo-SecureString $([System.Web.Security.Membership]::GeneratePassword(120, 50)) -AsPlainText -Force)
            Enabled                 = $true
            ChangePasswordAtLogon   = $true
            AccountNotDelegated     = $true
            SmartCardLogonRequired  = If ($SmartCardRequired -eq 'True') {$true} Else {$false}
            
        }
    
        Try {
            New-ADUser @UserDetails -ErrorAction Stop
            Write-ConditionalOutput "Account: $SamAccountName created"
            Write-ConditionalOutput $UserDetails
            
        }
    
        Catch {
            Write-Error $Error[0]
        }

        # Verify OU path
        Try { 
            Get-ADOrganizationalUnit $Tier0AccountOU -ErrorAction Stop | Out-Null
        }
    
        Catch {
            Throw "Organizational Unit '$Tier0AccountOU' doesn't exist in Active Directory"
        }

        # Helper function
        Function Add-UserToGroup {
        Param (
            [Parameter(Mandatory = $true)]
            [string]$GroupName,
        
            [Parameter(Mandatory = $true)]
            [string]$UserName
        )
    
        Try {
            Get-ADGroup $GroupName -ErrorAction Stop | Out-Null
            Add-ADGroupMember -Identity $GroupName -Members $UserName -ErrorAction Stop
            Write-ConditionalOutput "Account: $UserName added to group: $GroupName"
        } 
        Catch {
            Write-Warning "Group '$GroupName' not found, or error adding account: '$UserName' to the group"
        }
        }

        Add-UserToGroup -GroupName $Tier0UserGroup -UserName $SamAccountName
        Add-UserToGroup -GroupName $Tier0PrimaryGroup -UserName $SamAccountName
        Add-UserToGroup -GroupName $ProtectedUsersGroup -UserName $SamAccountName

        Try {
            
            # Change Primary Group for user
            $NewPrimaryGroup = Get-ADGroup $Tier0PrimaryGroup -properties @("primaryGroupToken")
            Get-ADUser $SamAccountName | Set-ADUser -replace @{primaryGroupID=$NewPrimaryGroup.primaryGroupToken} -ErrorAction Stop
            Remove-ADGroupMember -Identity 'Domain Users' -Members $SamAccountName -Confirm:$false -ErrorAction Stop
            Write-ConditionalOutput "Primary group changed to: '$Tier0PrimaryGroup' for account: $SamAccountName"
    
        }
    
        Catch {
            Write-Error $Error[0]
        }
}
