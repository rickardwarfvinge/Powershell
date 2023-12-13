# Advent Of Code 2023 https://adventofcode.com/
# Rickard Warfvinge
# Day 1 Part 2

$Array = Get-Content '.\Dec 1 puzzle input.txt'
$Sum = @()
$HashValues = @{ 
    'one' = '1'
    'two' = '2'
    'three' = '3'
    'four' = '4'
    'five' = '5'
    'six' = '6'
    'seven' = '7'
    'eight' = '8'
    'nine' = '9'
}

$Numbers = $HashValues.GetEnumerator() | ForEach-Object {$_.Key;$_.Value}
Foreach ($string in $Array)
{
$First = ($Numbers | ForEach-Object {Select-String -pattern $_ -InputObject $string -AllMatches}).Matches | Sort-Object Index | Select -ExpandProperty Value | Select -First 1
$Last = ($Numbers | ForEach-Object {Select-String -pattern $_ -InputObject $string -AllMatches}).Matches | Sort-Object Index | Select -ExpandProperty Value | Select -Last 1

$FirstValue = $HashValues.GetEnumerator() | Where-Object {$_.Value -eq ($Numbers -eq $First) -or $_.Key -eq ($Numbers -eq $First)} | select -ExpandProperty Value
$LastValue = $HashValues.GetEnumerator() | Where-Object {$_.Value -eq ($Numbers -eq $Last) -or $_.Key -eq ($Numbers -eq $Last)} | select -ExpandProperty Value

$TotalValue = $FirstValue+$LastValue
$Sum += $TotalValue
}

$Sum | Measure-Object -Sum
