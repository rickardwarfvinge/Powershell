    <#
    .SYNOPSIS
    Various Group Policy functions
    
    .DESCRIPTION
    Various Group Policy functions
    
    .EXAMPLE 
    Get-GPOsDisabled, Get-GPOsWithoutLinks, Get-GPOsNotApplied, Get-GPOsNoAuthGroup
    
    .FUNCTIONALITY
        List Group Policy related information
    
    .NOTES
        Author:  Rickard Warfvinge <rickard.warfvinge@gmail.com>
        Purpose: List Group Policy related information
    #>


# List GPOs that are disabled
Function Get-GPOsDisabled ()
{ 
 
    Foreach ($GPO in (Get-GPO -All))
   
    {
         
        If ($GPO.GpoStatus -eq 'AllSettingsDisabled')
        
        {
        
            [PSCustomObject]@{
            GpoName = $GPO.DisplayName
            GpoCreationDate = $GPO.CreationTime
            }
        
        }
                
    }
 
}
 

# List GPOs without any links
Function Get-GPOsWithoutLinks
{ 
 
    Foreach ($GPO in (Get-GPO -All))
   
    {
         
    If ([Bool]($GPO | Where-Object {$_ | Get-GPOReport -ReportType XML| Select-String -NotMatch "<LinksTo>"}) -eq $true)
        
        {
        
            [PSCustomObject]@{
            GpoName = $GPO.DisplayName
            GpoCreationDate = $GPO.CreationTime
            
            }
        
        }
                
    }
 
}
 

# List GPOs without the permission 'Apply Group Policy' in any of that GPOs security groups that are not being applied/used
Function Get-GPOsNotApplied
{ 
 
    Foreach ($GPO in (Get-GPO -All))
   
    {
        
        $Counter = 0
        Foreach ($GpoPermission in (Get-GPPermission -Guid $GPO.Id -All)) # Get GPO permissions
 
            {
            
            Foreach ($SecurityGroup in $GpoPermission) # Loop all security groups
 
                {If (($SecurityGroup | Select-Object -ExpandProperty Permission) -eq 'GpoApply') {$Counter ++}}
            
            }
            
                # If counter is less then 1 no security groups have 'GpoApply' set.
                If ($Counter -lt 1)
                
                {
                
                    [PSCustomObject]@{
                    GpoName = $GPO.DisplayName
                    GpoCreationDate = $GPO.CreationTime

                    }
                
                }
 
    }
 
}
 

# List GPOs that are missing the 'Authenticated Users' group
Function Get-GPOsNoAuthGroup
{ 
 
    Foreach ($GPO in (Get-GPO -All))
   
    {
            
        Try # If 'Authenticated Users' are missing there will be an error
 
        {
            
        Foreach ($GpoPermission in (Get-GPPermission -Guid $GPO.Id -TargetName 'Authenticated Users' -TargetType Group -ErrorAction Stop)){}
            
        }
            
        Catch # Autenticated users group removed from GPO
            
            {
            
            $GPOsWithoutAuth += $GPO.displayname + ',' # Add GPOs with no 'Authenticated Users' group
            
            }
            
    }
        
        # List GPO names with no 'Authenticated Users' group
        If ($GPOsWithoutAuth -ne $null)
        
        {
            $GPOsWithoutAuth = $GPOsWithoutAuth -split ','
            $GPOsWithoutAuth
            
        }
} 
