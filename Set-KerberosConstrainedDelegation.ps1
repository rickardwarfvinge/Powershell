
Function Set-KerberosConstrainedDelegation {

<#
    .DESCRIPTION
    Set Kerberos Constrained Delegation on User accounts, computer accounts or Group Managed Service accounts.
    Control if account is sensetive and cannot be delegated.
    Correct ServicePrincipalName(s) needs to be set on target object(s) before, or after this function is used.
        
    .REQUIREMENTS
    PS Module: ActiveDirectory
    
    .PARAMETER AccountName
    AccountName of user, computer or group manage service accounts
    
    .PARAMETER ServicePrincipalNames
    ServicePrincipalName(s) for delegation

    .PARAMETER Protocol
    Constrained delegation with Kerberos Only, or Protocol Transition/Trust (Use Any Authentication Protocol)
        
    .PARAMETER VerboseOutput
    Verbose console output, ON or OFF (Default: ON)
    
    .EXAMPLE 
    1. Set constrained delegation on account user01 for two service types (SPNs) using 'Any Authentication Protocol' with verbose output (default: ON)
        Set-KerberosConstrainedDelegation -AccountName user01 -ServicePrincipalNames http/test.domain.com, http/test1.domain.com -Protocol 'Use Any Authentication Protocol'
    
    2. Set constrained delegation on account user01 for one service type (SPN) using 'Kerberos Only' with verbose output OFF
        Set-KerberosConstrainedDelegation -AccountName gMSA-ScriptTest -ServicePrincipalNames http\test.adlab.shb.biz -Protocol 'Kerberos Only' -VerboseOutput OFF
    
    .AUTHOR
    Rickard Warfvinge, rickard.warfvinge@gmail.com
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
        [String]$AccountName,
        
        [Parameter(Mandatory=$true,
        HelpMessage="Enter one or more 'Service Principale Names' separated by commas.")]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1,256)]
        [ValidatePattern('^[a-zA-Z]+/[a-zA-Z0-9\.-]+(:[0-9]+)?$')]
        [String[]]$ServicePrincipalNames,

        [Parameter(Mandatory=$true,
        HelpMessage="Select 'Kerberos Only' or 'Any Authentication Protocol' (enforcing constrained delegation)")]
        [ValidateSet('Kerberos Only','Use Any Authentication Protocol')] 
        [String]$Protocol,

        [Parameter(Mandatory=$false,
        HelpMessage = "Turn verbose console output ON, or OFF")]
        [ValidateSet('ON','OFF')]    
        [String]$VerboseOutput = 'ON'
  
        )
        
        # Verify required module
        If ([Bool](Get-Module activedirectory) -eq $False) {
            Throw "Required ActiveDirectory module is not imported/installed."
        }

        # Verbose output to console?
        If ($VerboseOutput -eq 'ON') {
            $VerbosePreference = 'Continue'
        }

        # Message for console
        $VerboseOutputMessage = "Kerberos Constrained Delegation ($Protocol) enabled on account '$AccountName'. Service(s): $($ServicePrincipalNames -join ', ')."

        Switch ((Get-ADObject -Filter "Name -eq '$AccountName'").ObjectClass) {
        
            'User' # User account
                {
                If ((Get-ADUser $AccountName -Properties AccountNotDelegated).AccountNotDelegated -eq $true) {
                    Throw "Object '$AccountName' is sensetive and cannot be delegated"
                }
                
                If ($Protocol -eq 'Kerberos Only') {
                    Try {
                        Set-ADUser -Identity $AccountName -Add @{'msDS-AllowedToDelegateTo'= @($ServicePrincipalNames)} -TrustedForDelegation $False -ErrorAction Stop
                        Write-Verbose $VerboseOutputMessage
                    }
                    Catch {Throw $Error[0]}
                }
                Else { # Any Authentication Protocol
                    Try {
                        Set-ADUser -Identity $AccountName -Add @{'msDS-AllowedToDelegateTo'= @($ServicePrincipalNames)} -ErrorAction Stop
                        Set-ADAccountControl -Identity $AccountName -TrustedToAuthForDelegation $True -ErrorAction Stop
                        Write-Verbose $VerboseOutputMessage
                    }
                    Catch {Throw $Error[0]}
                    }
                }
            
            'Computer' # Computer account
                {
                If ((Get-ADComputer "$AccountName" -Properties AccountNotDelegated).AccountNotDelegated -eq $true) {
                    Throw "Object '$AccountName' is sensetive and cannot be delegated"
                }

                If ($Protocol -eq 'Kerberos Only') {
                    Try {
                        Set-ADComputer -Identity $AccountName -Add @{'msDS-AllowedToDelegateTo'= @($ServicePrincipalNames)} -TrustedForDelegation $False -ErrorAction Stop
                        Write-Verbose $VerboseOutputMessage
                    }
                    Catch {Throw $Error[0]}
                }
                Else { # Any Authentication Protocol
                    Try {
                        Set-ADComputer -Identity $AccountName -Add @{'msDS-AllowedToDelegateTo'= @($ServicePrincipalNames)} -ErrorAction Stop
                        Set-ADAccountControl -Identity "$AccountName$" -TrustedForDelegation $False -TrustedToAuthForDelegation $true -ErrorAction Stop
                        Write-Verbose $VerboseOutputMessage
                    }
                    Catch {Throw $Error[0]}
                }
            }
            
            'msDS-GroupManagedServiceAccount' # Group managed service account
                {
                If ($Protocol -eq 'Kerberos Only') {
                    Try {
                        Set-ADServiceAccount -Identity "$AccountName$" -Add @{'msDS-AllowedToDelegateTo'= @($ServicePrincipalNames)} -ErrorAction Stop
                        Set-ADAccountControl -Identity "$AccountName$" -TrustedForDelegation $false -TrustedToAuthForDelegation $false -ErrorAction Stop
                        Write-Verbose $VerboseOutputMessage
                    }
                    Catch {Throw $Error[0]}
                }
                Else { # Any Authentication Protocol
                    Try {
                        Set-ADServiceAccount -Identity "$AccountName$" -Add @{'msDS-AllowedToDelegateTo'= @($ServicePrincipalNames)} -ErrorAction Stop
                        Set-ADAccountControl -Identity "$AccountName$" -TrustedForDelegation $false -TrustedToAuthForDelegation $True -ErrorAction Stop
                        Write-Verbose $VerboseOutputMessage
                    }
                    Catch {Throw $Error[0]}
                }
            }
        }
}
