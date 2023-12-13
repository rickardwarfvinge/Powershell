# Advent Of Code 2023 https://adventofcode.com/
# Rickard Warfvinge
# Day 2 Part 2

$Array = Get-Content '.\Dec 2 puzzle input.txt'

$Sum = @()

Foreach ($Line in $Array)

{

$SubGames = ($Line -split '; ') -split ': ' -notmatch 'Game'
$Game = $SubGames -split ', ' -replace ' ', '=' | ForEach-Object {($_ -split '='  | sort -Descending) -join '='} | ConvertFrom-StringData
$RedValue = $Game.red | select -Unique | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
$GreenValue = $Game.green | select -Unique | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
$BlueValue = $Game.blue | select -Unique | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
$Total = $RedValue * $GreenValue * $BlueValue
$Sum += $Total

}

$Sum | Measure-Object -Sum
