Function Set-TempGroupAccess () {

 <#
    .SYNOPSIS
    Set time based group access using Privileged Access Management Feature of Active Directory
    
    .DESCRIPTION
    Set time based group access using Privileged Access Management Feature of Active Directory
    
    .PARAMETER UserName
    Name of Active Directory User
    
    .PARAMETER Group
    Name of Active Directory Group
    
    .PARAMETER TimeType
    Time type for TTL of group access. Options: seconds, minutes, hours and days
    
    .PARAMETER TTL
    Numeric value for the time how long the group access will last

    .VARIABLE PolicyMaxDays
    Variable used in the function to limit the amount of days or time that temporary group access can be granted. Change the value to suit your needs.

    .REQUIREMENTS
    Privileged Access Management Feature in your Active Directory forest needs to be enabled
    
    .EXAMPLE 
    1. Set-TempGroupAccess -UserName User01 -Group Group01 -TimeType Days -TTL 3
    2. Set-TempGroupAccess -UserName User01 -Group Group01 -TimeType Hours -TTL 24
    3. Set-TempGroupAccess -UserName User01 -Group Group01 -TimeType Minutes -TTL 45
    4. Set-TempGroupAccess -UserName User01 -Group Group01 -TimeType Seconds -TTL 600
    
    .FUNCTIONALITY
        Set time based group access using Privileged Access Management Feature of Active Directory
    
    .NOTES
        Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
        Purpose: Grant temporary group access to Active Directory security groups with option to limit access time to a value of your choice (PolicyMaxDays)
    #>

    [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)]
            [ValidateScript({Get-ADUser -Identity $_})]
            [string] $UserName,
            [Parameter(Mandatory=$true)]
            [ValidateScript({Get-AdGroup -Identity $_})]
            [string] $Group,
            [Parameter(Mandatory=$true)]
            [ValidateSet('Days','Hours','Minutes','Seconds')]
            [string] $TimeType,
            [Parameter(Mandatory=$true)]
            [string] $TTL

        )
    
# Verify if Privileged Access Management Feature is enabled in the domain
If ((Get-ADOptionalFeature -filter {Name -like "Privileged*"} | select -ExpandProperty IsDisableable) -eq $false)

    {

    $PolicyMaxDays = 5 # Maximal time for temporary group membership according to ACDI policy (5 days). Ok to change this value if new policy guidelines in the future
    
    Switch ($TimeType) # Define what TimeType that is selected and control that $PolicyMaxDays is not is exceeded
    
        {
    
        {$TimeType -eq 'Seconds'}
        
            {
            
            $NewTTL = New-TimeSpan -Seconds $TTL
            If ($NewTTL.TotalSeconds -gt ($PolicyMaxDays * 86400))
            {Write-Error "TTL of $($NewTTL.TotalSeconds) $TimeType exceeds the maximum allowed time which is $($PolicyMaxDays * 86400) $TimeType";Return}
            $ConsoleOutput = $NewTTL.TotalSeconds

            }

        {$TimeType -eq 'Minutes'}
        
            {
            
            $NewTTL = New-TimeSpan -Minutes $TTL
            If ($NewTTL.TotalMinutes -gt ($PolicyMaxDays * 1440))
            {Write-Error "TTL of $($NewTTL.TotalMinutes) $TimeType exceeds the maximum allowed time which is $($PolicyMaxDays * 1440) $TimeType";Return}
            $ConsoleOutput = $NewTTL.TotalMinutes

            }

        {$TimeType -eq 'Hours'}
        
            {
            
            $NewTTL = New-TimeSpan -Hours $TTL
            If ($NewTTL.TotalHours -gt ($PolicyMaxDays * 24))
            {Write-Error "TTL of $($NewTTL.TotalHours) $TimeType exceeds the maximum allowed time which is $($PolicyMaxDays * 24) $TimeType";Return}
            $ConsoleOutput = $NewTTL.TotalHours

            }

        {$TimeType -eq 'Days'}
        
            {
            
            $NewTTL = New-TimeSpan -Days $TTL
            If ($NewTTL.TotalDays -gt $PolicyMaxDays)
            {Write-Error "TTL of $($NewTTL.TotalDays) $TimeType exceeds the maximum allowed time which is $PolicyMaxDays $TimeType";Return}
            $ConsoleOutput = $NewTTL.TotalDays
            
            }
        
        }
     
    Add-ADGroupMember -Identity $Group -Members $UserName -MemberTimeToLive $NewTTL
    # Optional output to user. Enable if you need it
    # Write-Host "User $UserName have temporary access to AD-Group $Group for $ConsoleOutput $TimeType"
    
    }

Else {Write-Warning "PAM feature is not enabled in domain: $env:USERDNSDOMAIN"}

}
