Function New-GMSAAccount () {

<#
    
    .SYNOPSIS
    Create Group Manged Service Account and set PrincipalsAllowedToRetrieveManagedPassword

    .DESCRIPTION
    Create Group Manged Service Account and set PrincipalsAllowedToRetrieveManagedPassword
    
    .REQUIREMENTS
    Active Directory module installed and permissions to create and change Group Managed Service Accounts
    
    .PARAMETER OU
    DistinguishedName of organizational unit
    
    .PARAMETER VerboseOutput
    Turn Verbose console information on or off. Default is off.
    
    .PARAMETER UserName
    Name of Group Managed Service Account.
    
    .PARAMETER PrincipalsAllowedToRetrieveManagedPassword
    Array of computer, or group objects
    
    .EXAMPLE 
    1. New-GmsaAccount -UserName gMSA-Name -PrincipalsAllowedToRetrieveManagedPassword server1, server2, group01
    2. New-GmsaAccount -UserName gMSA-Name -PrincipalsAllowedToRetrieveManagedPassword server1
    3. New-GmsaAccount -UserName gMSA-Name -PrincipalsAllowedToRetrieveManagedPassword server1, server2
    
    .AUTHOR
    Rickard Warfvinge
    
#>

    [CmdletBinding()]
    Param(
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
        [string]$OU,
        
        [Parameter(Mandatory=$false,
        HelpMessage = "Turn verbose console output ON or OFF")]
        [ValidateSet('ON','OFF')]    
        [String]$VerboseOutput = 'OFF',
        
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

        [Parameter(Mandatory=$true,
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
        [String[]]$PrincipalsAllowedToRetrieveManagedPassword
           
        )
    
    # Turn verbose output on for console output
    If ($VerboseOutput -eq 'on') {$VerbosePreference = 'Continue'}

    Try { 
        
        # Array for storing adjusted object names for $PrincipalsAllowedToRetrieveManagedPassword. Computer objects need to get a trailing '$' character
        $Principals = @()
    
        Foreach ($Item in $PrincipalsAllowedToRetrieveManagedPassword)

            {

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
    
        # Verbose output to user
        Write-Verbose "Group managed service account '$UserName' created in '$OU'"
    
        # Set PrincipalsAllowedToRetrieveManagedPassword on Group managed service account
        Set-ADServiceAccount -Identity $UserName -PrincipalsAllowedToRetrieveManagedPassword $Principals
        
        # Verbose output to user
        Write-Verbose "PrincipalsAllowedToRetrieveManagedPassword is set to objects: $PrincipalsAllowedToRetrieveManagedPassword"

        }

    Catch {

        Write-Error $Error[0]
    
    }
 
}
 
