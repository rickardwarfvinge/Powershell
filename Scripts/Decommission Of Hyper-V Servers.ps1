﻿# 2024-03-06 - Rickard Warfvinge
# Script for decommission of servers in Hyper-V. Run Powershell ISE as admin and execute this on the Hyper-V server.
# Prerequisites: Failover Cluster Module, Hyper-V module and Powershell ISE executed with Administrator privileges.

# Verify script is running with Administrator privileges
If ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) {
    Write-Warning -Message "Your Powershell session needs to run with Administrator privileges." # Warning message
    Break # Stop script execution
}

# Protection for execution of entire script outside Powershell ISE.
If ($Host.Name -ne 'Windows PowerShell ISE Host') {
    Write-Warning "This script should be executed in Powershell ISE." # Warning message
    Break # Stop script execution
}

# Verifying prerequisite Powershell FailoverClusters module
If ([Bool](Get-Module FailoverClusters -ListAvailable) -eq $false) {
    Write-Warning "Failover Cluster Module for Windows PowerShell is a prerequisite for running this script." # Warning message
    Break # Stop script execution
}

# Verifying prerequisite Powershell Hyper-V module
If ([Bool](Get-Module Hyper-V -ListAvailable) -eq $false) {
    Write-Warning "Hyper-V Module for Windows PowerShell is a prerequisite for running this script." # Warning message
    Break # Stop script execution
}

# Get name of VM from user
$ServerName = Read-Host "Type in the name of the VM you want to remove"

# Change $ServerName to upper case for user output
$ServerName = $ServerName.ToUpper()

# Verify if VM exist, are a cluster member or not
If ((Get-ClusterGroup | Select-Object -ExpandProperty Name) -eq $ServerName) {
    Try {
        # Get VM from cluster (verification)
        Get-ClusterGroup -Name $ServerName -ErrorAction Stop -Verbose | Out-Null
    
        # Get the node where the VM resides
        $OwnerNode = (Get-ClusterGroup -Name $ServerName -ErrorAction Stop).OwnerNode.Name

        # Store VM path for later removal of VM folder
        $VmPath = (Get-VM -ComputerName $OwnerNode -Name $ServerName).Path

        # User information
        Write-Verbose "Storing owner node: $OwnerNode for VM $ServerName." -Verbose

        # User information
        Write-Verbose "Storing VM path: $VmPath for VM $ServerName." -Verbose

        # VM is member of cluster
        $ClusterMember = $true
        }
        
    Catch {
        Write-Warning $error[0] # Incorrect VM name input from user
        Break # Stop script execution
    }
    
} # End if

Else { # VM is not member of cluster
    Try {
            # Get the node where the VM resides
            $OwnerNode = Get-VM -Name $ServerName -ErrorAction Stop | select -ExpandProperty ComputerName
        
            # Store VM path for later removal of VM folder
            $VmPath = Get-VM -Name $ServerName  -ErrorAction Stop| Select-Object -ExpandProperty Path
        
            # User information
            Write-Verbose "Storing owner node: $OwnerNode for VM $ServerName." -Verbose

            # User information
            Write-Verbose "Storing VM path: $VmPath for VM $ServerName." -Verbose
        
            # VM is not member of cluster
            $ClusterMember = $false
    }
        
    Catch {
        Write-Warning $error[0] # Incorrect VM name input from user
        Break # Stop script execution
    }

} # End else

# User information
Write-Verbose "VM $ServerName is selected for removal." -Verbose

If ($ClusterMember -eq $true) {
    Write-Verbose "VM $ServerName is a member of cluster $($(Get-Cluster).Name)." -Verbose
}

Else {
    Write-Verbose "VM $ServerName is a not a member of any cluster." -Verbose
}

# Get all nodes in the cluster
$AllClusterNodes = Get-ClusterNode | Select-Object -ExpandProperty Name

# User information
Write-Verbose "Retreive all cluster nodes from cluster: $((Get-Cluster).Name)." -Verbose

# User information
Write-Verbose "Found the following cluster nodes: $AllClusterNodes." -Verbose

# User information
Write-Verbose "Retreiving all virtual machines from cluster." -Verbose

# Get all VMs from all nodes
$AllVMs = $AllClusterNodes | ForEach-Object {Get-VM -ComputerName $_}

# Used for verification that no warnings remains
$WarningTrigger = $false

# User information
Write-Verbose "Scanning all virtual machines for any misconfiguration such as other VMs configuration or disk files pointing to $ServerName's folder." -Verbose

# Get all possible path related properties from all VMs to be certain that no other VM have configured disk files,
# configuration files etc that are located in $ServerName VM folder. This verification is done because a misconfiguration
# of a VM that resides in another folder then it's name must be verified. VM $ServerName is excluded for explainable reasons.
# Loop all VMs, $ServerName excluded
Foreach ($VM in $AllVMs | Where-Object {$_.Name -ne $ServerName})
    {
    # If any specific part of all path related string equals $ServerName a warning message will be displayed in the console and $WarningTrigger will be set to $true
    Switch ($VM) {
        {$Vm.Path -match $ServerName}
            {
            Write-Warning "VM $($Vm.Name)'s (VM Configuration Files Location) is located in $ServerName's VM folder. Reconfigure $($Vm.Name) before you continue with removal of $ServerName."
            $WarningTrigger = $true
            }
        
        {$Vm.CheckpointFileLocation -match $ServerName}
            {
            Write-Warning "VM $($Vm.Name)'s (Checkpoint File Location) is located in $ServerName's VM folder. Reconfigure $($Vm.Name) before you continue with removal of $ServerName."
            $WarningTrigger = $true
            }
        
        {$Vm.SmartPagingFilePath -match $ServerName}
            {
            Write-Warning "VM $($Vm.Name)'s (Smart Paging File Location) is located in $ServerName's VM folder. Reconfigure $($Vm.Name) before you continue with removal of $ServerName."
            $WarningTrigger = $true
            }
        
        {$Vm.SnapshotFileLocation -match $ServerName}
            {
            Write-Warning "VM $($Vm.Name)'s (Snapshot File Location) is located in $ServerName's VM folder. Reconfigure $($Vm.Name) before you continue with removal of $ServerName."
            $WarningTrigger = $true
            }
        
        {(($VM | Get-VMHardDiskDrive | Select-Object -ExpandProperty Path) -match $ServerName)}
            {
            Write-Warning "VM $($Vm.Name)'s (Virtual Disk Files Location) is located in $ServerName's VM folder. Reconfigure $($Vm.Name) before you continue with removal of $ServerName."
            $WarningTrigger = $true
            }

    } # End switch
    
} # End foreach


# No warnings = Stop VM, Remove VM, Remove VM from cluster, Remove $ServerName VM folder
If ($WarningTrigger -eq $False) {
    # User information with aproval from user to continue
    Write-Verbose "No misconfigured VMs where found that points to VM $ServerName's folder." -Verbose
    Write-Verbose "VM $ServerName will be stopped, deleted, removed from the cluster (if member) and folder '$(($VmPath -split '\\')[-1])' from path '$VmPath' will be deleted. Proceed?" -Verbose
    Pause # User input required

    Try { # Stop VM
        # Check if VM is running
        If ((Get-VM -ComputerName $OwnerNode -Name $ServerName).State -eq 'Running') {
            # Stop VM
            Stop-VM -ComputerName $OwnerNode -Name $ServerName -ErrorAction Stop -Force -Verbose
    
            # User information
            Write-Verbose "VM $ServerName is stopped." -Verbose
        }
        
        # User information
        Else {Write-Verbose "VM $ServerName is already in 'Off' state." -Verbose}

    }

    Catch {Write-Error $Error[0]}

    Try {
        # Check if VM is off
        If ((Get-VM -ComputerName $OwnerNode -Name $ServerName).State -eq 'Off') {
            # Remove VM
            Remove-VM -ComputerName $OwnerNode -Name $ServerName -ErrorAction Stop -Force -Verbose
    
            # User information
            Write-Verbose "VM $ServerName is deleted." -Verbose

        }
    
        Else {Write-Error $Error[0]}

    }

    Catch {Write-Error $Error[0]}
    
    # If VM is clustred, remove VM from the cluster and it's resources
    If ($ClusterMember -eq $true) {
        # Remove VM from cluster
        Remove-ClusterGroup -Name $ServerName -RemoveResources -Force -Verbose
    
        # User information
        Write-Verbose "VM $ServerName is removed from cluster $((Get-Cluster).Name)." -Verbose
        }

    # Remove VM folder
    Remove-Item $VmPath -Verbose -Recurse

    # User information
    Write-Verbose "Folder '$(($VmPath -split '\\')[-1])' in path '$VmPath' is deleted." -Verbose
    Write-Verbose "Decommission of VM $ServerName is complete." -Verbose

    }

Else {
    Write-Warning "There are still files/folders that relates to other VMs that resides in $ServerName's folder '$VmPath'. Before deletion of that folder no other VM can have files pointing there."
}