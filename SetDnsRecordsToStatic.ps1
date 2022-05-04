<#
    
    .SYNOPSIS
    Set DNS resource records from dynamic to static on multiple servers
    
    .DESCRIPTION
    Set DNS resource records from dynamic to static on multiple servers
    
    .FUNCTIONALITY
        Set DNS resource records from dynamic to static on multiple servers
    
    .NOTES
        Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
        Purpose: Set DNS resource records from dynamic to static on multiple servers

#>
 
$Servers = Get-ADComputer -Filter {servicePrincipalName -notlike "*cluster*"} -Properties OperatingSystem | Where-Object {$_.enabled -eq $true -and $_.operatingsystem -like "*server*"} | Select-Object -ExpandProperty name
$ZoneName = 'yourdomain.com'
Foreach ($Server in $Servers)
 
{
 
    If (Get-DnsServerResourceRecord -Name $Server -ZoneName $ZoneName -RRType A | Where-Object {$_.timestamp -ne $null})
 
    {
 
    $OldObj = Get-DnsServerResourceRecord -Name $server -ZoneName $ZoneName -RRType "A"
    $NewObj = $OldObj.Clone()
    $NewObj.TimeToLive = [System.TimeSpan]::FromHours(0)
    Set-DnsServerResourceRecord -NewInputObject $NewObj -OldInputObject $OldObj -ZoneName $ZoneName -PassThru
    
    }
 
} 