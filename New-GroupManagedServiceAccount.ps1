Function New-GroupManagedServiceAccount {

<#
    .SYNOPSIS
    Create Group Manged Service Account, set PrincipalsAllowedToRetrieveManagedPassword (optional) and add account to group(s) (optional)

    .DESCRIPTION
    Create Group Manged Service Account, set (optional) PrincipalsAllowedToRetrieveManagedPassword and join account to default groups
    
    .PARAMETER OU
    DistinguishedName of organizational unit (Default OU: T0-Service Accounts).
    
    .PARAMETER UserName
    Name of Group Managed Service Account.

    .PARAMETER Groups
    Name of group(s) that the Group Managed Service Account should be member of
    
    .PARAMETER PrincipalsAllowedToRetrieveManagedPassword
    Array of computer, or group objects

    .PARAMETER Quiet
    Sub function (Write-ConditionalOutput) to toggle console output ON/OFF with -Quiet switch
    
    .EXAMPLE 
    PS> GroupManagedServiceAccount -UserName gMSA-Name

    Create Group Managed Service account

    .EXAMPLE 
    PS> New-GroupManagedServiceAccount -UserName gMSA-Name -PrincipalsAllowedToRetrieveManagedPassword server1, Group10, Server2

    Create Group Managed Service account and set PrincipalsAllowedToRetrieveManagedPassword

    .EXAMPLE 
    PS> New-GroupManagedServiceAccount -UserName gMSA-Name -OU "OU=test,DC=domain,DC=com" -Quiet

    Create Group Managed Service account, set OU location instead of default OU and suppress output
    
    .NOTES
        Requirements: Powershell Module: ActiveDirectory
        Author: Rickard Warfvinge
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage = "Enter the name of the Group Managed Service Account you want to create.")]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1,15)]
        [ValidateScript(
            {$UserName = $_
            If(Get-ADObject -Filter "Name -eq '$UserName'") {
                Throw "Group Managed Service Account '$UserName' already exist in Active Directory."
                }
            Else {
                $true
                }
            }
        )]
        [String]$UserName,

        [Parameter(Mandatory=$false,
        HelpMessage = "Enter DistinguishedName to organizational unit (OU)")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            {$OU = $_
            If (Get-ADObject -Filter "DistinguishedName -eq '$OU'" | Select-Object -ExpandProperty DistinguishedName) {
            $True
            }
            Else {
                Throw "'$OU' has incorrect syntax or doesn't exist in Active Directory"
                }
            }
        )]
        [string]$OU = "OU=T0-Service Accounts,OU=Tier 0,$((Get-ADDomain).DistinguishedName)",

        [Parameter(Mandatory=$false,
        HelpMessage = "Enter computer(s) and/or group(s) to give permission to retrieve the password for the Group Managed Service Account")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            {$PrincipalsAllowedToRetrieveManagedPassword = $_
            If(Get-ADObject -Filter "Name -eq '$PrincipalsAllowedToRetrieveManagedPassword'" | Where-Object {$_.ObjectClass -eq 'Computer' -or $_.ObjectClass -eq 'Group'}) {
                $true
                }
            Else {Throw "'$PrincipalsAllowedToRetrieveManagedPassword' is a disallowed object type for Group Managed Service Accounts"}
            }
        )]
        [String[]]$PrincipalsAllowedToRetrieveManagedPassword,

        [Parameter(Mandatory=$false,
        HelpMessage = "Input the name(s) of the group(s) that the new Group Managed Service Account should be joined to.")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            {If(Get-ADObject -Filter "Name -eq '$_'") {
                $true
                }
            Else {
                Throw "The AD-Group '$_' dont exist in Active Directory."
                }
            }
        )]
        [String[]]$Groups,
        
        [Parameter(Mandatory=$false,
        HelpMessage = "Toggle console write output ON/OFF using -Quiet switch.")]
        [Switch]$Quiet
   
        )
    
    Function Write-ConditionalOutput {
        Param (
            [String]$Message
        )
        If (-Not $Quiet) {
            Write-Output $Message
        }
    }

    # Default groups for Tier structure
    $DefaultGroups = @('Tier 0 Service Accounts', 'Read-Tier0')

        Try { 
            $Principals = @() # Array for storing adjusted object names for $PrincipalsAllowedToRetrieveManagedPassword. Computer objects need to get a trailing '$' character
            Foreach ($Item in $PrincipalsAllowedToRetrieveManagedPassword) {
                $Object = Get-ADObject -Filter "Name -eq '$Item'"
                    If ($Object.ObjectClass -eq 'Computer') {
                        $Principals += "$($Object.Name)$"
                    }
                    Else {
                        $Principals += $Object.Name
                    }

            }
            
            # Group managed service account is created
            New-ADServiceAccount -Name $UserName -Enabled $true -DNSHostName "$UserName.$env:USERDNSDOMAIN" -Path $OU -ErrorAction Stop
            Write-ConditionalOutput "Group Managed Service Account: '$UserName' created in OrganizationalUnit: '$OU'"
            
            If ($Null -ne $PrincipalsAllowedToRetrieveManagedPassword) {
                # Set PrincipalsAllowedToRetrieveManagedPassword on Group managed service account
                Set-ADServiceAccount -Identity $UserName -PrincipalsAllowedToRetrieveManagedPassword $Principals
                Write-ConditionalOutput "PrincipalsAllowedToRetrieveManagedPassword is set to object(s): $PrincipalsAllowedToRetrieveManagedPassword"

            }

            $DefaultGroups | ForEach-Object {
                Try {
                    Get-ADGroup $_ -ErrorAction SilentlyContinue | Out-Null
                    Add-ADGroupMember -Identity $_ -Members "$UserName$" -Confirm:$false
                    Write-ConditionalOutput "Group Managed Service Account '$UserName' added to group: $_"
                    }
                Catch {
                    Write-Warning "DefaultGroup(s): $($DefaultGroups -join ',') dont exist in domain: $($env:USERDNSDOMAIN.ToLower())"
                }
            }

                If ($Null -ne $Groups) {

                Try {
                    $Groups | ForEach-Object {
                        Add-ADGroupMember -Identity $_ -Members "$UserName$" -Confirm:$false
                        Write-ConditionalOutput "Group Managed Service Account '$UserName' added to group: $_"
                        }
                    
                }

                Catch {
                    Write-Error $Error[0]
                }

            }

        }

        Catch {
            Write-Error $Error[0]
        }
}