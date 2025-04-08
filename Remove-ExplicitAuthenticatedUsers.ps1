Function Remove-ExplicitAuthenticatedUsers () {

<#
    .SYNOPSIS
    Remove-ExplicitAuthenticatedUsers

    .DESCRIPTION
    Remove 'Authenticated Users' explicit ACL on OrganizationalUnit object

    .EXAMPLE
    PS> Remove-ExplicitAuthenticatedUsers -OuDistinguishedName 'OU=test,DC=domain,DC=com'

    Removes explicit ACL(s) for 'Authenticated Users' on the selected OU
    
    .EXAMPLE
    PS> Remove-ExplicitAuthenticatedUsers -OuDistinguishedName 'OU=test,DC=domain,DC=com' -ConsoleOutput OFF

    Removes explicit ACL(s) for 'Authenticated Users' on the selected OU with no output to console

    .PARAMETER OuDistinguishedName
    distinguishedName of OrganizationalUnit object

    .PARAMETER ConsoleOutput
    Console output, ON or OFF (Default: ON)
    
    .NOTES
        Requirements: Powershell Module: ActiveDirectory
        Author: Rickard Warfvinge
#>

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true,
    HelpMessage = "Enter DistinguishedName to organizational unit (OU).")]
    [ValidateScript({
        If (Get-ADObject -Filter "distinguishedName -eq '$_'" | Where-Object {$_.ObjectClass -eq 'organizationalUnit'}) {
            $true
        }
        Else {
            Throw "DistinguishedName of organizationalUnit: '$_' cannot be found in Active Directory."
        }
    }
)]
[String]$OuDistinguishedName,

    [Parameter(Position = 1, Mandatory=$false,
    HelpMessage = "Turn console output ON, or OFF")]
    [ValidateSet('ON','OFF')]    
    [String]$ConsoleOutput = 'ON'
)

$ACL = Get-Acl -Path "AD:$OuDistinguishedName"
$ACEs = $ACL.Access | Where-Object {$_.IdentityReference -eq "NT AUTHORITY\Authenticated Users" -and $_.IsInherited -eq $false}
    
If ($ACEs) {
    Foreach ($ACE in $ACEs) {
        $ACL.RemoveAccessRule($ACE) | Out-Null
    }
    Try {
        $ACL | Set-Acl -Path "AD:$OuDistinguishedName"
        If ($ConsoleOutput -eq 'ON') {
            Write-Verbose "Explicit 'Authenticated Users' ACE(s) have been removed from OU: '$OuDistinguishedName'" -Verbose
        }
    }
    Catch {
        Write-Error "Failed to apply updated ACL: $($_.Exception.Message)"
    }
}
Else {
    Write-Warning "No explicit 'Authenticated Users' ACE(s) found on OU: '$OuDistinguishedName'"
}
}
