Function Set-ArrayCorrection () {

    <#
    
    .SYNOPSIS
    Compare two arrays and adjust the second array to be an exact match of the first one
    
    .DESCRIPTION
    Compare two arrays and adjust the second array to be an exact match of the first one
    
    .PARAMETER Array1
    Array you want to use as layout (correct one)
    
    .PARAMETER Array2
    Array you want to match and correct against Array1
    
    .EXAMPLE 
    Set-ArrayCorrection -Array1 'Stockholm', 'Helsinki', 'Paris', 'London', 'Arizona' -Array2 'Stockholm', 'Dallas', 'Paris', 'London', 'Brussel'
    
    .FUNCTIONALITY
    Compare two arrays and adjust the second array to be an exact match of the first one
    
    .NOTES
        Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
        Purpose: Compare two arrays and adjust the second array to be an exact match of the first one
    #>
    
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true)]
            [string[]]$Array1,
            [Parameter(Mandatory=$true)]
            [string[]]$Array2
            
        )
    
    $DifferentElements = Compare-Object -ReferenceObject $Array1 -DifferenceObject $Array2 -PassThru | Where-Object {$_.sideIndicator -eq "=>"}
     
    Foreach ($Element in $DifferentElements) {
     
        # Set the value from the correct position in $Array1 to the corresponding postition in $Array2
        $Array2.SetValue($Array1[$Array2.IndexOf($Element)],$Array2.IndexOf($Element))
     
    }
     
        If (-Not (Compare-Object -ReferenceObject $Array1 -DifferenceObject $Array2 -PassThru) -eq "")
        {Write-Warning "Arrays cannot be matched!"}
    
    $Array1
    $Array2
    
    }