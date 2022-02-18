<#
    
    .SYNOPSIS
    Remove duplicate DNS records
    
    .DESCRIPTION
    Remove duplicate DNS records
    
    .FUNCTIONALITY
        Removes duplicate DNS records in AD DNS
    
    .NOTES
        Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
        Purpose: If duplicate DNS records are found they are being removed. Pause after each duplicate record. Can
                 be removed for faster execution.

#>

Import-Module dnsserver
$VerbosePreference = 'Continue'
$DnsServer = 'DNS01'
$DnsZone = 'dnsdomain'
 
# Get all A-records from a specific zone with a few exclusions
[System.Collections.ArrayList]$DnsRecords = Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $DnsZone -RRType A | where {$_.TimeStamp -ne $Null}
$ExcludedRecords = @(
'domaindnszones',
'forestdnszones',
'gc._msdcs'
'@'
)
 
# Exclusions removed from array
Foreach ($Record in $DnsRecords | where {$ExcludedRecords -contains $_.HostName}) {$DnsRecords.Remove($Record)}
 
# Sorted list of IPV4 addresses
$SortedIPV4List = (($DnsRecords.RecordData).IPV4Address).IpAddressToString | Sort-Object
# Removing duplicates
$UniqueIPV4List = $SortedIPV4List | Get-Unique
 
Foreach ($Address in $UniqueIPV4List)
 
{
 
# Get Hostname(s) related to a specific IPV4Address. Slow but works...
$HostNames = $DnsRecords | where {($_.RecordData).IPV4Address -eq $Address}
 
    If ($HostNames.count -gt 1) # If there is more then one HostName registred to that specific IPV4 address then there is ducplication.
 
    {
 
     # Store the Record with the newest TimeStamp
     $NewestRecord = ($HostNames.TimeStamp).ToShortDateString() | Sort-Object | Select-Object -Last 1
     
         # Loop HostName variable
         Foreach ($Record in $HostNames | Sort-Object TimeStamp -Descending)
 
         {
            
            # If the Records TimeStamp not equals to $NewestRecord TimeStamp then we can remove it.
            If (($Record.TimeStamp).ToShortDateString() -eq $NewestRecord)
            
            {
            
            Write-Verbose "This Record have the newest date and will NOT be removed."
            $Record
            
            }
            
            Else
            
            {
            
            Write-Verbose "Duplicate record(s) that will be removed."
            $Record
            Pause
            Remove-DnsServerResourceRecord -ZoneName $DnsZone -RRType "A" -Name $Record.HostName -RecordData (($Record.RecordData).IPv4Address).IPAddressToString -Force
            Write-Verbose "DNS record with HostName: '$($Record.HostName)' and IP Address: '$((($Record.RecordData).IPv4Address).IPAddressToString)' have been removed."
 
            }
            
         }
 
    }
     
} 
