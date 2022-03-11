Function Get-VerifiedUser {

<#

.SYNOPSIS
Get Active Directory User from user input and verify that the user exist in AD. Loop until a correct username is provided

.DESCRIPTION
Get Active Directory User from user input and verify that the user exist in AD. Loop until a correct username is provided

.EXAMPLE 
Get-VerifiedUser
$User = Get-VerifiedUser

.FUNCTIONALITY
    Get Active Directory User from user input and verify that the user exist in AD. Loop until a correct username is provided

.NOTES
    Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
    Purpose: Get Active Directory User from user input and verify that the user exist in AD. Loop until a correct username is provided

#>


Try {If ((Get-Module ActiveDirectory) -eq $Null) {Import-Module ActiveDirectory -ErrorAction Stop}}
Catch {Write-Warning "$($error[0].Exception.Message)";Break}

Do {
   
    Try {

    $UserName = Get-ADUser -Identity (Read-Host "Type in an Active Directory UserName" -ErrorAction Stop)

    }

    Catch {

    $UserName = $Null
    Write-Warning "The UserName you typed in cannot be found in Active Directory. Please try again"

    }
 
      }
 
Until ($UserName -ne $Null)
$UserName

}