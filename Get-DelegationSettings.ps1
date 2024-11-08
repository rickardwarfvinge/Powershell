Function Get-DelegationSettings {

<#
    .SYNOPSIS
    Get Delegation Settings

    .DESCRIPTION
    Get delegation settings for use accounts, computer accounts and Group Managed Service accounts
    Correct ServicePrincipalName(s) needs to be set on target object(s) before, or after this function is used.

    .PARAMETER AccountName
    AccountName of user, computer or group manage service accounts

    .EXAMPLE
    PS> Get-DelegationSettings -AccountName user01

    Get delegation details for user account: user01

    .NOTES
        Requirements: Powershell Module: ActiveDirectory
        Author: Rickard Warfvinge
#>

[CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="Allowed Active Directory Objects: User, Computer or Group Managed Service Accounts.")]
        [ValidateScript( {
            If(Get-ADObject -Filter "Name -eq '$_'" | Where-Object {$_.ObjectClass -eq 'Computer' -or $_.ObjectClass -eq 'User' -or $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount'}) {
                $true
            }
            Else {
                Throw "Object '$_' cannot be found in Active Directory or '$_' is an disallowed object type."
            }
        }
        )]
        [String]$AccountName
        
        )
        
        # Verify required module
        If ([Bool](Get-Module activedirectory) -eq $False) {
            Throw "Required ActiveDirectory module is not imported/installed."
        }

        Switch ((Get-ADObject -Filter "Name -eq '$AccountName'").ObjectClass) {
        
            'User' {
                $Object = Get-ADUser $AccountName -Properties *
                $ObjectType = 'User'
                Write-Verbose "ObjectType: $ObjectType" -Verbose
                Write-Verbose "AccountName: $($Object.Name)" -Verbose

                Switch ($Object) {
                    
                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $False -and $Null -ne ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Account is trusted for delegation - Constrained Delegation - Kerberos Only" -Verbose
                        Write-Verbose "Service Principal Name(s) (services) of attribute 'msDS-AllowedToDelegateTo' where account: $($Object.Name) is allowed to delegate to: $($Object |
                        Select-Object -ExpandProperty msDS-AllowedToDelegateTo)" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $True -and $Null -ne ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Account is trusted for delegation - Constrained Delegation - Use Any Authentication Protocol" -Verbose
                        Write-Verbose "Service Principal Name(s) (services) of attribute 'msDS-AllowedToDelegateTo' where account: $($Object.Name) is allowed to delegate to: $($Object |
                        Select-Object -ExpandProperty msDS-AllowedToDelegateTo)" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $False -and $Null -eq ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Do not trust this user for delegation (no delegation enabled)" -Verbose
                    }

                    {$Object.AccountNotDelegated -eq $True} {
                        Write-Verbose "Account is sensetive and cannot be delegated" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $True} {
                        Write-Verbose "Account is trusted for delegation - Unconstrained Delegation" -Verbose
                    }

                }
            
            }
            
            'Computer' {
                $Object = Get-ADComputer $AccountName -Properties *
                $ObjectType = 'Computer'
                Write-Verbose "ObjectType: $ObjectType" -Verbose
                Write-Verbose "Computer Name: $($Object.Name)" -Verbose

                Switch ($Object) {
                    
                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $False -and $Null -ne ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Account is trusted for delegation - Constrained Delegation - Kerberos Only" -Verbose
                        Write-Verbose "Service Principal Name(s) (services) of attribute 'msDS-AllowedToDelegateTo' where account: $($Object.Name) is allowed to delegate to: $($Object |
                        Select-Object -ExpandProperty msDS-AllowedToDelegateTo)" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $True -and $Null -ne ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Account is trusted for delegation - Constrained Delegation - Use Any Authentication Protocol" -Verbose
                        Write-Verbose "Service Principal Name(s) (services) of attribute 'msDS-AllowedToDelegateTo' where account: $($Object.Name) is allowed to delegate to: $($Object |
                        Select-Object -ExpandProperty msDS-AllowedToDelegateTo)" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $False -and $Null -eq ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Do not trust this computer for delegation (no delegation enabled)" -Verbose
                    }

                    {$Object.AccountNotDelegated -eq $True} {
                        Write-Verbose "Account is sensetive and cannot be delegated" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $True} {
                        Write-Verbose "Account is trusted for delegation - Unconstrained Delegation" -Verbose
                    }
                }
            }
            
            'msDS-GroupManagedServiceAccount' {
                $Object = Get-ADServiceAccount $AccountName -Properties *
                $ObjectType = 'Group Managed Service Account'
                Write-Verbose "ObjectType: $ObjectType" -Verbose
                Write-Verbose "Account: $($Object.Name)" -Verbose

                Switch ($Object) {
                    
                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $False -and $Null -ne ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Account is trusted for delegation - Constrained Delegation - Kerberos Only" -Verbose
                        Write-Verbose "Service Principal Name(s) (services) of attribute 'msDS-AllowedToDelegateTo' where account: $($Object.Name) is allowed to delegate to: $($Object |
                        Select-Object -ExpandProperty msDS-AllowedToDelegateTo)" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $True -and $Null -ne ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Account is trusted for delegation - Constrained Delegation - Use Any Authentication Protocol" -Verbose
                        Write-Verbose "Service Principal Name(s) (services) of attribute 'msDS-AllowedToDelegateTo' where account: $($Object.Name) is allowed to delegate to: $($Object |
                        Select-Object -ExpandProperty msDS-AllowedToDelegateTo)" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $False -and $Object.TrustedToAuthForDelegation -eq $False -and $Null -eq ($Object | Select-Object -ExpandProperty msDS-AllowedToDelegateTo)} {
                        Write-Verbose "Do not trust this computer for delegation (no delegation enabled)" -Verbose
                    }

                    {$Object.AccountNotDelegated -eq $True} {
                        Write-Verbose "Account is sensetive and cannot be delegated" -Verbose
                    }

                    {$Object.TrustedForDelegation -eq $True} {
                        Write-Verbose "Account is trusted for delegation - Unconstrained Delegation" -Verbose
                    }
                }
            }
        }
}