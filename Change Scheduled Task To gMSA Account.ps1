Function Set-ScheduledScriptGmsaAccount () {

<#

.SYNOPSIS
Change account to Group Managed Service Account for scheduled task

.DESCRIPTION
Change account to Group Managed Service Account for scheduled task

.PARAMETER gMSAname
Name of group managed service account

.PARAMETER TaskName
Name of scheduled task

.EXAMPLE 
Set-ScheduledscriptGmsaAccount -gMSAname 'gmsa-server01' -Taskname 'My scheudled task'

.FUNCTIONALITY
    Change account to Group Managed Service Account for scheduled task

.NOTES
    Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
    Purpose: Change scheduled task to use group managed service account instead of regular service account or user account
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string] $gMSAname,
        [Parameter(Mandatory=$true)]
        [string] $Taskname
        
    )

If (-Not($gMSAname.EndsWith('$'))) {$gMSAname = $gMSAname + '$'} # If no trailing $ character in gMSA name, add $ sign

# Test gMSA account and get scheduled task
Try {

Test-ADServiceAccount -Identity $gMSAname -ErrorAction Stop
Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop

}

Catch {Write-Warning $($_.Exception.Message);Break}



# Change user account to gMSA for scheduled task
$Principal = New-ScheduledTaskPrincipal -UserID "$env:USERDNSDOMAIN\$gMSAname" -LogonType Password
Try {Set-ScheduledTask $TaskName -Principal $Principal -ErrorAction Stop}
Catch {Write-Warning $($_.Exception.Message);Break}

}