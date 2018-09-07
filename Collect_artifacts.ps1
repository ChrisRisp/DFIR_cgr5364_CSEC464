# File:   Collect_Artifacts.ps1
# Author: Christian Rispoli
# Class:  CSEC 464
#

#Array for Hosts to PSRemote
$TargetHosts = ""

# Collect Time Information
function Get-Time{
    $obj = @{}
    
    $currtime = Get-Date 
    $timezone = Get-TimeZone | select -ExpandProperty StandardName
    $boottime = Get-CimInstance -ClassName win32_operatingsystem | select -ExpandProperty lastbootuptime
    $uptime = New-TimeSpan -Start $boottime -End $currtime

    $obj.CurrTime = $currtime
    $obj.TimeZone = $timezone
    $obj.UpTime = $uptime

    $obj | Format-Table
    $obj | Export-Csv -NoTypeInformation -Path "time.csv" -Delimiter ","
    
}

# Collect Operating System Version 
function Get-Os{
    
    $os_info = Get-CimInstance -ClassName Win32_OperatingSystem |Select-Object Caption, Version, OSArchitecture
    

    $os_info | Format-Table
    $os_info | Export-Csv -NoTypeInformation -Path "os.csv" -Delimiter ","
}

# Collect Hardware Specifications
function Get-Spec{
    $obj = @{}

    $cpu_info = Get-WmiObject win32_processor 
    $ram_size = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))}

    $obj.RamCapacity_Gb = $ram_size

    $cpu_info | Format-Table
    $obj| Format-Table

    $cpu_info | Export-Csv -NoTypeInformation -Path "sys1.csv" -Delimiter ","
    $obj | Export-Csv -NoTypeInformation -Path "sys2.csv" -Delimiter ","

}

function Get-Storage{
    $obj = @{}

    $Disks= Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, Size
    $Disks | Format-Table

    $Disks | Export-Csv -NoTypeInformation -Path "disks.csv" -Delimiter ","
}

function Get-AD{
    $obj = @{}

    $Domain = (Get-WmiObject win32_computersystem).Domain
    #$obj.DomainController = Get-ADDomainController -Discover -Domain $Domain

    $obj | Format-Table
    $obj | Export-Csv -NoTypeInformation -Path "ad.csv" -Delimiter ","
}

function Get-Host{
    $obj = @{}


    $obj.Hostname = (Get-WmiObject win32_computersystem).DNSHostName
    $obj.Domain = (Get-WmiObject win32_computersystem).Domain

    $obj | Format-Table
    $obj | Export-Csv -NoTypeInformation -Path "host.csv" -Delimiter ","
}

function Get-Users{
    $obj = @{}
    $users = Get-WmiObject -Class Win32_UserAccount
    $boottime = Get-CimInstance -ClassName win32_operatingsystem | select -ExpandProperty lastbootuptime
    $logins = Get-EventLog security | Where-Object {$_.TimeGenerated -gt $boottime} | Where-Object {($_.InstanceID -eq 4634) -or ($_.InstanceID -eq 4624)} | Select-Object Index,TimeGenerated,InstanceID,Message

    $users | Format-Table
    $logins | Format-Table
    $logins | Export-Csv -NoTypeInformation -Path "users.csv" -Delimiter ","
    $users | Export-Csv -NoTypeInformation -Path "users.csv" -Delimiter ","
}

function Get-Networking{
    $obj = @{}
    $obj.Interfaces = Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress
    $obj.ARP_Table = Get-NetNeighbor
    $obj.RoutingTable = Get-NetRoute
    $obj.AdvancedInfo = (ipconfig /all)

    $ListenTCPConnections = (Get-NetTCPConnection | Where-Object {($_.State -eq "Listen")})
    $obj.ListeningProcesses = $ListenTCPConnections
    $EstTCPConnections = (Get-NetTCPConnection | Where-Object {($_.State -eq "Established")})
    $obj.EstablishedConnections = $EstTCPConnections

    $UDPEndpoints = Get-NetUDPEndpoint
    $obj.UDPEndpoints = $UDPEndpoints
  
    $obj.DNSCache = Get-DnsClientCache

    $obj.ARP_Table | Format-Table
    $obj.Interfaces | Format-Table
    $obj.AdvancedInfo | Format-Table
    $obj.RoutingTable | Format-Table
    $obj.ListeningProcesses | Format-Table
    $obj.UDPEndpoints | Format-Table
    $obj.EstablishedConnections | Format-Table
    $obj.DnsCache | Format-Table

    $obj.ARP_Table | Export-Csv -NoTypeInformation -Path networkarptable.csv
    $obj.Interfaces | Export-Csv -NoTypeInformation -Path networkinterfaces.csv
    $obj.AdvancedInfo | Export-Csv -NoTypeInformation -Path networkadvancedinfo.csv
    $obj.RoutingTable | Export-Csv -NoTypeInformation -Path networkroutingtable.csv
    $obj.ListeningProcesses | Export-Csv -NoTypeInformation -Path networklistening.csv
    $obj.UDPEndpoints | Export-Csv -NoTypeInformation -Path networkudp.csv
    $obj.EstablishedConnections | Export-Csv -NoTypeInformation -Path networkestablished.csv
    $obj.DnsCache | Export-Csv -NoTypeInformation -Path networkdnscache.csv

}

function Get-Processes{
    $obj = @{}
    $obj.List = Get-WmiObject Win32_Process | Select-Object ProcessName,ProcessID,ParentProcessID
    $obj.Path = Get-Process | Select-Object Path

    $obj.List | Format-Table
    $obj.Path | Format-Table

    $obj.List | Export-Csv -NoTypeInformation -Path installedlist.csv
    $obj.Path | Export-Csv -NoTypeInformation -Path installedpath.csv
}

function Get-Drivers{
    $obj = @{}
    $obj.List = Get-WindowsDriver -Online -All | Select-Object Driver, BootCritical, OriginalFileName, Version, Date, ProviderName

    $obj.List | Format-Table

    $obj.List | Export-Csv -NoTypeInformation -Path drivers.csv

}

function Get-Software{
    $obj = @{}
    $sw = Get-WmiObject -Class Win32_Product
    $sw | Format-Table
    $sw | Export-Csv -NoTypeInformation -Path "sw.csv" -Delimiter ","

}

function Get-UserFiles{
    $obj = @{}


    foreach($Folder in Get-ChildItem -Path 'C:\Users') {
        if(Test-Path "C:\Users\$($Folder.Name)\Documents") {
            $Downloads = Get-ChildItem -Path "C:\Users\$($Folder.Name)\Documents" -Recurse -File 
            $Downloads | Format-Table
            $Downloads | Export-Csv -NoTypeInformation -Path files1.csv

        }
        if(Test-Path "C:\Users\$($Folder.Name)\Downloads") {
            $Documents = Get-ChildItem -Path "C:\Users\$($Folder.Name)\Downloads" -Recurse -File
            $Documents | Format-Table
            $Documents | Export-Csv -NoTypeInformation -Path files2.csv

        }
    }
  
}

function Write-Csv{
    $currtime = (Get-Date).toString()
    $timezone = Get-TimeZone | select StandardName
    $uptime = Get-CimInstance -ClassName win32_operatingsystem | select csname, lastbootuptime
    
    Write-Host $timezone
    Write-Host $uptime
    Write-Host $currtime
}


# Combine CSVs for Email
function Concat-Csv{
    Set-Location $pwd
    Get-ChildItem -Path $pwd -Filter *.csv | ForEach-Object {
        [System.IO.File]::AppendAllText("$pwd/artifacts", [System.IO.File]::ReadAllText($_.FullName))
        Remove-Item $_
    }
}

# Main Function
function Collect-Artifacts{
    Write-Host ":::::::::::::::::::::::::: Collecting Time ::::::::::::::::::::::::::"
    Get-Time
    
    Write-Host ":::::::::::::::::::::::::: Collecting OS Info :::::::::::::::::::::::"
    Get-Os
    
    Write-Host ":::::::::::::::::::::::::: Collecting HW Specs ::::::::::::::::::::::"
    Get-Spec
    
    Write-Host ":::::::::::::::::::::::: Collecting Storage Specs :::::::::::::::::::"
    Get-Storage
    #Get-AD
    
    Write-Host ":::::::::::::::::::::::: Collecting FQDN Info :::::::::::::::::::::::"
    Get-Host
    
    Write-Host "::::::::::::::::::::::::: Collecting User Info :::::::::::::::::::::::"
    Get-Users

    Write-Host "::::::::::::::::::::::::: Collecting Installed SW :::::::::::::::::::::::"
    Get-Software

    Write-Host "::::::::::::::::::::::::: Collecting Network Info ::::::::::::::::::::"
    Get-Networking
     
    Write-Host "::::::::::::::::::::::::: Collecting Process Info ::::::::::::::::::::"
    Get-Processes
   
    Write-Host "::::::::::::::::::::::::: Collecting Driver Info ::::::::::::::::::::"
    Get-Drivers
   
    Write-Host "::::::::::::::::::::::::: Collecting User Files :::::::::::::::::::::"
    Get-UserFiles

    Concat-Csv
}

Collect-Artifacts