# Advent Of Code 2023 https://adventofcode.com/
# Rickard Warfvinge
# Day 1 Part 1

$Array = Get-Content '.\Dec 1 puzzle input.txt'
$Sum = @()
Foreach ($Line in $Array)
{
$Line = $Line -replace "[^0-9]"
If ($Line.Length -gt 1) {$Line = $Line[0] + $Line[-1]}
Else {$Line = $Line[0] + $Line[0]}
$Sum += $Line
}
$Sum | Measure-Object -Sum
