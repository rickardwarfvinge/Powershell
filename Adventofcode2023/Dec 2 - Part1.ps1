
# Advent Of Code 2023 https://adventofcode.com/
# Rickard Warfvinge
# Day 2 Part 1

$Array = Get-Content '.\Dec 2 puzzle input.txt'

$Sum = @()
$RedCubes = 12
$GreenCubes = 13
$BlueCubes = 14

Foreach ($Line in $Array)

{

$GameID = ($Line-split ':')[0] -replace 'Game ', ' '.Trim()
$SubGames = ($Line -split '; ') -split ': ' -notmatch 'Game'
$Counter = @()

    Foreach ($Game in $SubGames)

    {
    
    $BlueOK = $null
    $GreenOK = $null
    $RedOK = $null
    $Game = $Game -split ', '

    Switch ($Game)

    {

    {$Game -match 'green'}
    
        {
        
        [int]$Number = (($Game | Select-String -Pattern 'green') -split ' ')[0]
        If ($Number -le $GreenCubes) {$GreenOK = $True} Else {$GreenOK = $False}

        }

    {$Game -match 'red'}

        {
        
        [int]$Number = (($Game | Select-String -Pattern 'red') -split ' ')[0]
        If ($Number -le $RedCubes) {$RedOK = $True} Else {$RedOK = $False}

        }

    {$Game -match 'blue'}

        {
        
        [int]$Number = (($Game | Select-String -Pattern 'blue') -split ' ')[0]
        If ($Number -le $BlueCubes) {$BlueOK = $True} Else {$BlueOK = $False}

        }

    }

    If ($GreenOK -eq $False -or $RedOK -eq $False -or $BlueOK -eq $False) {} # Not possible game
    Else {$Counter += $GameID} # Possible game

    }

If ($SubGames.Length -eq $Counter.Length) {$Sum += $GameID}

}

$Sum | Measure-Object -Sum
