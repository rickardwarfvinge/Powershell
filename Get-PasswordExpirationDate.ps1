
Function Get-PasswordExpiration {

    <#
    
    .SYNOPSIS
    Check password expiration date on AD user account with support for Fine Grained Password Policies
    
    .DESCRIPTION
    Check password expiration date on AD user account with support for Fine Grained Password Policies
    
    .PARAMETER UserName
    Name of user
    
    .EXAMPLE 
    Get-PasswordExpiration -UserName user01
    
    .FUNCTIONALITY
        Check password expiration on AD user account. Support if user have FGPP policies applies.
        Check if password have expired and if password never expires is enabled.
    
    .NOTES
        Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
        Purpose: Get information regarding password expiration dates on AD user accounts.
    
    #>
    
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)]
            [string] $UserName
            
        )
    
    Try {$User = Get-ADUser -Identity $UserName -ErrorAction SilentlyContinue -Properties PasswordLastSet, msDS-ResultantPSO, PasswordExpired, PasswordNeverExpires}
    Catch {write-host "The username you typed in dont exist in Active Directory. Please try again.";break}
        
    $ResultantPSO = Get-ADUserResultantPasswordPolicy -Identity $User # Get users Password FGPP policy if it exist. Will be empty if password have expired
    
    If (($User.PasswordLastSet -ne $null) -and $User.PasswordNeverExpires -ne $true)
    
    {
            
        # No FGPP applied on this user account or password have expired (FGPP).
        If ($ResultantPSO -eq $Null -or $User.PasswordExpired -eq $true) 
            
        {
    
        # Password have expired
        If ($User.PasswordLastSet -lt (Get-date).AddDays(-(Get-ADDefaultDomainPasswordPolicy | select -ExpandProperty MaxPasswordAge).Days))
        {Write-Host "$($User.samaccountname)'s password expired on $($User.PasswordLastSet)"}
    
        Else
    
        {
    
        $PasswordPolicyDays = (Get-ADDefaultDomainPasswordPolicy | select -ExpandProperty MaxPasswordAge).Days  # Max PasswordAge in Default Domain Policy (No FGPP)
        $DaysSincePasswordChange = ((Get-Date) - $User.PasswordLastSet).Days # Number of days since the user changed his/her password
        $DaysUntilExpire = $PasswordPolicyDays - $DaysSincePasswordChange
        Write-host "$($User.samaccountname)'s password will expire in: $DaysUntilExpire days"
    
        }
            
        }
    
        Else # FGPP applied
    
        {
            
        $FGPPolicyApplied = Get-ADFineGrainedPasswordPolicy -Filter * | where {$_.DistinguishedName -eq $User.'msDS-ResultantPSO'}
        $PasswordPolicyDays = ($FGPPolicyApplied | select -ExpandProperty MaxPasswordAge).Days
            
            If ($PasswordPolicyDays -ne 0) # If FGPP policy have setting 'password never expires' enabled value is zero.
            
            {
    
            $DaysSincePasswordChange = ((Get-Date) - $User.PasswordLastSet).Days
            $DaysUntilExpire = $PasswordPolicyDays - $DaysSincePasswordChange
            Write-host "$($User.samaccountname)'s password will expire in: $DaysUntilExpire days. FGPP: '$($FGPPolicyApplied.Name)'"
    
            }
    
            Else {Write-host "$($User.samaccountname)'s password will never expire due to FGPP: '$($FGPPolicyApplied.Name)'"}
            
            }
    
        }
    
    Else 
    
    {
        
        Switch ($User)
    
        {
    
        {$User.PasswordLastSet -eq $null} {Write-Host "$($User.SamAccountName)'s password has expired or 'User must change password at next logon' is checked."}
        {$User.PasswordNeverExpires -eq $true} {Write-Host "$($User.SamAccountName)'s password is set to 'Never Expires'. PasswordLastSet: $($User.PasswordLastSet)"}
    
        }
      
    }
    
    }
    