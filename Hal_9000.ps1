<#
    .SYNOPSIS  
        A bunch of stuff. 

    .DESCRIPTION  
          What are you doing Dave?

    .NOTES  
        File Name      : Hal_9000.ps1
        Version        : v.0.1  
        Author         : StillWorthless
        Email          : 
        Prerequisite   : PowerShell
        Created        : 29JAN16
     
     .CHANGELOG
        Update         : DATE
            Changes:   : 

     .TODO
        1. 

    ####################################################################################


#>
$Script:curDate = ""
$Script:curDate = $((Get-Date).ToString("yyyy_MMM_dd-HH.mm.ss-tt")) ##Sets the date and time##


# ===========================================================================================
#
# Function Name 'Get_Folder_Path' - Prompts for folder path to store files
#
# ===========================================================================================
Function Get_Folder_Path
{
    $objShell = ""
    $Script:NamedFolder = ""
    $Script:Log_File = ""
    $Script:Folder_Path = ""
    $objShell = new-object -com shell.application
    $Script:NamedFolder = $objShell.BrowseForFolder(0,"Please select where to save the log files to:",0,"$env:USERPROFILE\Desktop")
    if ($Script:NamedFolder -eq $null) {
        Write-Host "YOU MUST SELECT A FOLDER TO STORE THE LOGS!" -Fore Red
        . Get_Folder_Path }
    Else {
        $Script:Folder_Path = $Script:NamedFolder.self.path
        write-host "psNameFind will write all files to: $Script:Folder_Path"
        New-Item -type file -force "$Script:Folder_Path\Log_File_$Script:curDate.txt" | Out-Null
        $Script:Log_File = "$Script:Folder_Path\Log_File_$Script:curDate.txt"
        New-Item -type file -force "$Script:Folder_Path\Results_File_$Script:curDate.txt" | Out-Null
        $Script:Results_File = "$Script:Folder_Path\Results_File_$Script:curDate.txt"
        # ====================================
        # Starting the Log_File
        # ====================================
        echo "Script started - "$Script:curDate | out-file $Script:Log_File -Append
        echo "--------------------------------------------------------------" | out-file $Script:Log_File -Append }
}

# ========================================================================
# Function Name 'ListComputers' - Takes entered domain and lists all computers
# ========================================================================
Function ListComputers
{
    $DN = ""
    $Response = ""
    $DNSName = ""
    $DNSArray = ""
    $objSearcher = ""
    $colProplist = ""
    $objComputer = ""
    $objResults = ""
    $colResults = ""
    $Computer = ""
    $comp = ""
    New-Item -type file -force "$Script:Folder_Path\Computer_List_$Script:curDate.txt" | Out-Null
    $Script:Compute = "$Script:Folder_Path\Computer_List_$Script:curDate.txt"
    $strCategory = "(ObjectCategory=Computer)"
    
    Write-Host "Would you like to automatically pull from your domain or provide your own domain?"
    Write-Host "Auto pull uses the current domain you are on, if you need to select a different domain use manual."
    $response = Read-Host = "[1] Auto Pull, [2] Manual Selection"
    
    If($Response -eq "1") {
        $DNSName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        If($DNSName -ne $Null) {
            $DNSArray = $DNSName.Split(".") 
            for ($x = 0; $x -lt $DNSArray.Length ; $x++) {  
                if ($x -eq ($DNSArray.Length - 1)){$Separator = ""}else{$Separator =","} 
                [string]$DN += "DC=" + $DNSArray[$x] + $Separator  } }
        $Script:Domain = $DN
        echo "Pulled computers from: "$Script:Domain | Out-File $Script:Log_File -Append
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$Script:Domain")
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        foreach ($i in $colPropList) {
            $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
	elseif($Response -eq "2")
    {
        <#
            This is where an admin can build the tool to utilize their OU structure. If you feel that you do not 
            want to utilize this method you can replace the section labeled # EDITABLE SECTION START and END with the below:

            $Script:Domain = Read-Host "Enter your Domain here: OU=systems,DC=ds,DC=company,DC=com"
        #>
        
        # EDITABLE SECTION START
        $Script:Domain = Read-Host "Enter your Domain here: OU=systems,DC=ds,DC=company,DC=com"
        # EDITABLE SECTION END

        echo "Pulling computers from: "$Script:Domain | Out-File $Script:Log_File -Append
        $objOU = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Script:Domain")
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objOU
        $objSearcher.Filter = $strCategory
        $objSearcher.PageSize = 100000
        $objSearcher.SearchScope = "SubTree"
        $colProplist = "name"
        foreach ($i in $colPropList) { $objSearcher.propertiesToLoad.Add($i) }
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults) {
            $objComputer = $objResult.Properties
            $comp = $objComputer.name
            echo $comp | Out-File $Script:Compute -Append }
        $Script:Computers = (Get-Content $Script:Compute) | Sort-Object
    }
    else {
        Write-Host "You did not supply a correct response, Please select a response." -foregroundColor Red
        . ListComputers }
}

# ========================================================================
# Function Name 'ListTextFile' - Enumerates Computer Names in a text file
# Create a text file and enter the names of each computer, IP, or subnet. 
# One computer name, IP, or subnet per line. Supply the path to the text 
# file when prompted.
# ========================================================================
Function ListTextFile 
{
	$file_Dialog = ""
    $file_Name = ""
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $file_Dialog = New-Object System.Windows.Forms.OpenFileDialog
    $file_Dialog.InitialDirectory = "$env:USERPROFILE\Desktop"
    $File_Dialog.Filter = "All files (*.*)| *.*"
    $file_Dialog.MultiSelect = $False
    $File_Dialog.ShowHelp = $True
    $file_Dialog.ShowDialog() | Out-Null
    $file_Name = $file_Dialog.Filename
    $Comps = Get-Content $file_Name
    If ($Comps -eq $Null) {
        Write-Host "Your file was empty. You must select a file with at least one computer in it." -Fore Red
        . ListTextFile }
    Else
    {
        $Script:Computers = @()
        ForEach ($Comp in $Comps)
        {
            If ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
            {
                $Temp = $Comp.Split("/")
                $IP = $Temp[0]
                $Mask = $Temp[1]
                . Get-Subnet-Range $IP $Mask
                $Script:Computers += $Script:IPList
            }
            Else
            {
                $Script:Computers += $Comp
            }
        }

        echo " " | Out-File $Script:Log_File -Append
        echo "Computer list located: $file_Name" | Out-File $Script:Log_File -Append 
        
    }
}

# ========================================================================
# Function Name 'SingleEntry' - Enumerates Computer from user input
# ========================================================================
Function SingleEntry 
{
    $Comp = Read-Host "Enter Computer Name or IP (1.1.1.1) or IP Subnet (1.1.1.1/24)"
    If ($Comp -eq $Null) { . SingleEntry }
    ElseIf ($Comp -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}")
    {
        $Temp = $Comp.Split("/")
        $IP = $Temp[0]
        $Mask = $Temp[1]
        . Get-Subnet-Range $IP $Mask
        $Script:Computers = $Script:IPList
    }
    Else
    { $Script:Computers = $Comp} 
}

# ========================================================================
# Get-Subnet-Range Found this online at 
# http://www.indented.co.uk/index.php/2010/01/23/powershell-subnet-math/
# This takes the inputs from the admin and if the entry is a subnet this 
# will break the subnet out and build a list to be used by the tool.
# ========================================================================
Function Get-Subnet-Range {
    #.Synopsis
    # Lists all IPs in a subnet.
    #.Example
    # Get-Subnet-Range -IP 192.168.1.0 -Netmask /24
    #.Example
    # Get-Subnet-Range -IP 192.168.1.128 -Netmask 255.255.255.128        
    Param(
        [string]
        $IP,
        [string]
        $netmask
    )  
    Begin {
        $IPs = New-Object System.Collections.ArrayList

        Function Get-NetworkAddress {
            #.Synopsis
            # Get the network address of a given lan segment
            #.Example
            # Get-NetworkAddress -IP 192.168.1.36 -mask 255.255.255.0
            Param (
                [string]
                $IP,
               
                [string]
                $Mask,
               
                [switch]
                $Binary
            )
            Begin {
                $NetAdd = $null
            }
            Process {
                $BinaryIP = ConvertTo-BinaryIP $IP
                $BinaryMask = ConvertTo-BinaryIP $Mask
                0..34 | %{
                    $IPBit = $BinaryIP.Substring($_,1)
                    $MaskBit = $BinaryMask.Substring($_,1)
                    IF ($IPBit -eq '1' -and $MaskBit -eq '1') {
                        $NetAdd = $NetAdd + "1"
                    } elseif ($IPBit -eq ".") {
                        $NetAdd = $NetAdd +'.'
                    } else {
                        $NetAdd = $NetAdd + "0"
                    }
                }
                if ($Binary) {
                    return $NetAdd
                } else {
                    return ConvertFrom-BinaryIP $NetAdd
                }
            }
        }
       
        Function ConvertTo-BinaryIP {
            #.Synopsis
            # Convert an IP address to binary
            #.Example
            # ConvertTo-BinaryIP -IP 192.168.1.1
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                Foreach ($octet in $IP.split('.')) {
                    $strout = $null
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            [string]$strout = $strout + "1"
                        } else {
                            [string]$strout = $strout + "0"
                        }  
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }
 
 
        Function ConvertFrom-BinaryIP {
            #.Synopsis
            # Convert from Binary to an IP address
            #.Example
            # Convertfrom-BinaryIP -IP 11000000.10101000.00000001.00000001
            Param (
                [string]
                $IP
            )
            Process {
                $out = @()
                Foreach ($octet in $IP.split('.')) {
                    $strout = 0
                    0..7|% {
                        $bit = $octet.Substring(($_),1)
                        IF ($bit -eq 1) {
                            $strout = $strout + [math]::pow(2,(7-$_))
                        }
                    }
                    $out += $strout
                }
                return [string]::join('.',$out)
            }
        }

        Function ConvertTo-MaskLength {
            #.Synopsis
            # Convert from a netmask to the masklength
            #.Example
            # ConvertTo-MaskLength -Mask 255.255.255.0
            Param (
                [string]
                $mask
            )
            Process {
                $out = 0
                Foreach ($octet in $Mask.split('.')) {
                    $strout = 0
                    0..7|% {
                        IF (($octet - [math]::pow(2,(7-$_)))-ge 0) {
                            $octet = $octet - [math]::pow(2,(7-$_))
                            $out++
                        }
                    }
                }
                return $out
            }
        }
 
        Function ConvertFrom-MaskLength {
            #.Synopsis
            # Convert from masklength to a netmask
            #.Example
            # ConvertFrom-MaskLength -Mask /24
            #.Example
            # ConvertFrom-MaskLength -Mask 24
            Param (
                [int]
                $mask
            )
            Process {
                $out = @()
                [int]$wholeOctet = ($mask - ($mask % 8))/8
                if ($wholeOctet -gt 0) {
                    1..$($wholeOctet) |%{
                        $out += "255"
                    }
                }
                $subnet = ($mask - ($wholeOctet * 8))
                if ($subnet -gt 0) {
                    $octet = 0
                    0..($subnet - 1) | %{
                         $octet = $octet + [math]::pow(2,(7-$_))
                    }
                    $out += $octet
                }
                for ($i=$out.count;$i -lt 4; $I++) {
                    $out += 0
                }
                return [string]::join('.',$out)
            }
        }

        Function Get-IPRange {
            #.Synopsis
            # Given an Ip and subnet, return every IP in that lan segment
            #.Example
            # Get-IPRange -IP 192.168.1.36 -Mask 255.255.255.0
            #.Example
            # Get-IPRange -IP 192.168.5.55 -Mask /23
            Param (
                [string]
                $IP,
               
                [string]
                $netmask
            )
            Process {
                iF ($netMask.length -le 3) {
                    $masklength = $netmask.replace('/','')
                    $Subnet = ConvertFrom-MaskLength $masklength
                } else {
                    $Subnet = $netmask
                    $masklength = ConvertTo-MaskLength -Mask $netmask
                }
                $network = Get-NetworkAddress -IP $IP -Mask $Subnet
               
                [int]$FirstOctet,[int]$SecondOctet,[int]$ThirdOctet,[int]$FourthOctet = $network.split('.')
                $TotalIPs = ([math]::pow(2,(32-$masklength)) -2)
                $blocks = ($TotalIPs - ($TotalIPs % 256))/256
                if ($Blocks -gt 0) {
                    1..$blocks | %{
                        0..255 |%{
                            if ($FourthOctet -eq 255) {
                                If ($ThirdOctet -eq 255) {
                                    If ($SecondOctet -eq 255) {
                                        $FirstOctet++
                                        $secondOctet = 0
                                    } else {
                                        $SecondOctet++
                                        $ThirdOctet = 0
                                    }
                                } else {
                                    $FourthOctet = 0
                                    $ThirdOctet++
                                }  
                            } else {
                                $FourthOctet++
                            }
                            Write-Output ("{0}.{1}.{2}.{3}" -f `
                            $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                        }
                    }
                }
                $sBlock = $TotalIPs - ($blocks * 256)
                if ($sBlock -gt 0) {
                    1..$SBlock | %{
                        if ($FourthOctet -eq 255) {
                            If ($ThirdOctet -eq 255) {
                                If ($SecondOctet -eq 255) {
                                    $FirstOctet++
                                    $secondOctet = 0
                                } else {
                                    $SecondOctet++
                                    $ThirdOctet = 0
                                }
                            } else {
                                $FourthOctet = 0
                                $ThirdOctet++
                            }  
                        } else {
                            $FourthOctet++
                        }
                        Write-Output ("{0}.{1}.{2}.{3}" -f `
                        $FirstOctet,$SecondOctet,$ThirdOctet,$FourthOctet)
                    }
                }
            }
        }
    }
    Process {
        #get every ip in scope
        Get-IPRange $IP $netmask | %{
        [void]$IPs.Add($_)
        }
        $Script:IPList = $IPs
    }
}

Function Get_Processes
{
    Param(
        $computer
    )
    
    Write-Host "Creating Processes file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\Processes.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\Processes.txt"
    Echo "ProcessName|ProcessId|ParentProcessId|Name|Caption|Description|InstallDate|CreationDate|Path|CommandLine|ExecutablePath|FileSize|CreationTime|LastAccessTime|LastWriteTime|InternalName|OriginalName|VI_FileVersion|FileDescription|VI_Product|VI_ProductVersion|Language|CompanyName" | Out-File $Write_File
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer processes...." -ForegroundColor Yellow
    $Processes = Get-WmiObject -ComputerName $Computer Win32_Process
    ForEach($Process in $Processes)
    {
        #$NewPath = ($Service.PathName -split $regex)[0] -replace '"',''
        #Write-Host $NewPath -ForegroundColor Red
        $NewPath = $Process.ExecutablePath
        If($NewPath -ne $Null){ $fileEval = Get-Item -Path $NewPath }
        $Process | Select ProcessName,ProcessId,ParentProcessId,Name,Caption,Description,InstallDate,CreationDate,Path,CommandLine,ExecutablePath, @{Name="FileSize";Expression={$fileEval.Length}}, @{Name="CreationTime";Expression={$($FileEval.CreationTimeUtc)}}, `
        @{Name="LastAccessTime";Expression={$($FileEval.LastAccessTimeUtc)}}, @{Name="LastWriteTime";Expression={$($FileEval.LastWriteTimeUtc)}}, @{Name="InternalName";Expression={$($FileEval.VersionInfo.InternalName)}}, `
        @{Name="OriginalName";Expression={$($FileEval.VersionInfo.OriginalFilename)}}, @{Name="VI_FileVersion";Expression={$($FileEval.VersionInfo.FileVersion)}}, @{Name="FileDescription";Expression={$($FileEval.VersionInfo.FileDescription)}}, `
        @{Name="VI_Product";Expression={$($FileEval.VersionInfo.Product)}}, @{Name="VI_ProductVersion";Expression={$($FileEval.VersionInfo.ProductVersion)}}, @{Name="Language";Expression={$($FileEval.VersionInfo.Language)}}, `
        @{Name="CompanyName";Expression={$($FileEval.VersionInfo.CompanyName)}} | ConvertTo-Csv -Delimiter "|" -NoTypeInformation | Select-Object -Skip 1 | % {$_.Replace('"','')} | Out-File $Write_File -Append
        $Process = "" 
        $fileEval = ""
    }
    Write-Host "Done." -ForegroundColor Magenta

    echo "Got processes from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append

}

Function Get_Services
{
    Param(
        $computer
    )
    
    Write-Host "Creating Services file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\Services.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\Services.txt"
    Echo "SystemName|DesktopInteract|ErrorControl|Name|PathName|ServiceType|StartMode|State|DisplayName|FullName|FileSize|CreationTime|LastAccessTime|LastWriteTime|InternalName|OriginalName|VI_FileVersion|FileDescription|VI_Product|VI_ProductVersion|Language|CompanyName" | Out-File $Write_File
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer Services...." -ForegroundColor Yellow
    $regex = '^*\s-[a-zA-Z0-9]\s*|^*\s/[a-zA-Z0-9]*'
    $Services = Get-WmiObject -ComputerName $Computer Win32_Service
    ForEach($service in $Services)
    {
        $NewPath = ($Service.PathName -split $regex)[0] -replace '"',''
        #Write-Host $NewPath -ForegroundColor Red
        If($NewPath -ne $Null){ $fileEval = Get-Item -Path $NewPath }
        $Service | Select SystemName,DesktopInteract,ErrorControl,Name,PathName,ServiceType,StartMode,State,DisplayName, @{Name="FullName";Expression={$fileEval.FullName}}, @{Name="FileSize";Expression={$fileEval.Length}}, @{Name="CreationTime";Expression={$($FileEval.CreationTimeUtc)}}, `
        @{Name="LastAccessTime";Expression={$($FileEval.LastAccessTimeUtc)}}, @{Name="LastWriteTime";Expression={$($FileEval.LastWriteTimeUtc)}}, @{Name="InternalName";Expression={$($FileEval.VersionInfo.InternalName)}}, `
        @{Name="OriginalName";Expression={$($FileEval.VersionInfo.OriginalFilename)}}, @{Name="VI_FileVersion";Expression={$($FileEval.VersionInfo.FileVersion)}}, @{Name="FileDescription";Expression={$($FileEval.VersionInfo.FileDescription)}}, `
        @{Name="VI_Product";Expression={$($FileEval.VersionInfo.Product)}}, @{Name="VI_ProductVersion";Expression={$($FileEval.VersionInfo.ProductVersion)}}, @{Name="Language";Expression={$($FileEval.VersionInfo.Language)}}, `
        @{Name="CompanyName";Expression={$($FileEval.VersionInfo.CompanyName)}} | ConvertTo-Csv -Delimiter "|" -NoTypeInformation | Select-Object -Skip 1 | % {$_.Replace('"','')} | Out-File $Write_File -Append
        $Service = "" 
        $fileEval = ""
    } 
    Write-Host "Done." -ForegroundColor Magenta

    echo "Got Services from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append

}

Function Get_Drives
{
    Param(
        $computer
    )
    
    Write-Host "Creating Drives file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\Drives.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\Drives.txt"
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer Services...." -ForegroundColor Yellow
    Get-WmiObject win32_logicaldisk -ComputerName $Computer | Select Name,Description,Caption,DeviceID,DriveType,FileSystem,VolumeSerialNumber | ConvertTo-Csv -Delimiter "|" -NoTypeInformation | % {$_.Replace('"','')} | Out-File $Write_File -Append
    Write-Host "Done." -ForegroundColor Magenta

    echo "Got Drives from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

Function Get_Tasks
{
    Param(
        [string]$ComputerName,
        [switch]$RootFolder = $_
    )
    
    Write-Host "Creating Scheduled Tasks file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$ComputerName\Tasks.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$ComputerName\Tasks.txt"
    Write-Host "Done." -ForegroundColor Magenta

    #region Functions
    function Get-AllTaskSubFolders {
        [cmdletbinding()]
        param (
            # Set to use $Schedule as default parameter so it automatically list all files
            # For current schedule object if it exists.
            $FolderRef = $Schedule.getfolder("\")
        )
        if ($FolderRef.Path -eq '\') {
            $FolderRef
        }
        if (-not $RootFolder) {
            $ArrFolders = @()
            if(($Folders = $folderRef.getfolders(1))) {
                $Folders | ForEach-Object {
                    $ArrFolders += $_
                    if($_.getfolders(1)) {
                        Get-AllTaskSubFolders -FolderRef $_
                    }
                }
            }
            $ArrFolders
        }
    }

    function Get-TaskTrigger {
        [cmdletbinding()]
        param (
            $Task
        )
        $Triggers = ([xml]$Task.xml).task.Triggers
        if ($Triggers) {
            $Triggers | Get-Member -MemberType Property | ForEach-Object {
                $Triggers.($_.Name)
            }
        }
    }
    #endregion Functions


    try {
	    $Schedule = New-Object -ComObject 'Schedule.Service'
    } catch {
	    Write-Warning "Schedule.Service COM Object not found, this script requires this object"
	    return
    }

    $Schedule.connect($ComputerName) 
    $AllFolders = Get-AllTaskSubFolders

    foreach ($Folder in $AllFolders) {
        if (($Tasks = $Folder.GetTasks(1))) {
            $Tasks | Foreach-Object {
	            New-Object -TypeName PSCustomObject -Property @{
	                'Name' = $_.name
                    'Path' = $_.path
                    'State' = switch ($_.State) {
                        0 {'Unknown'}
                        1 {'Disabled'}
                        2 {'Queued'}
                        3 {'Ready'}
                        4 {'Running'}
                        Default {'Unknown'}
                    }
                    'Enabled' = $_.enabled
                    'LastRunTime' = $_.lastruntime
                    'LastTaskResult' = $_.lasttaskresult
                    'NumberOfMissedRuns' = $_.numberofmissedruns
                    'NextRunTime' = $_.nextruntime
                    'Author' =  ([xml]$_.xml).Task.RegistrationInfo.Author
                    'UserId' = ([xml]$_.xml).Task.Principals.Principal.UserID
                    'Description' = ([xml]$_.xml).Task.RegistrationInfo.Description
                    'Trigger' = Get-TaskTrigger -Task $_
                    'ComputerName' = $Schedule.TargetServer
                }
            } | ConvertTo-Csv -Delimiter "|" -NoTypeInformation | % {$_.Replace('"','')} | Out-File $Write_File -Append 
        }
    }
    Write-Host "Done." -ForegroundColor Magenta

    echo "Got Scheduled Tasks from $ComputerName" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

Function Get_Shares
{
    Param(
        $Computer
    )
    $Shares = @()
    Write-Host "Creating Remote Shares file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\RemoteShares.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\RemoteShares.txt"
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer Remote Shares...." -ForegroundColor Yellow
    $HKUrootkey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::Users,$computer) #Connects to remote HKU Registry Hive
        if(-not $HKUrootkey) { echo "Can't open the remote $Script:HKUroot registry hive" | Out-File $Script:Log_File -Append }
    $HKUSIDNames = $HKURootKey.GetSubKeyNames() #gets all HKU users SIDS
        if(-not $HKUSIDNames) { echo "Can't open $Script:HKUroot on $Computer" | Out-File $Script:Log_File -Append }
    ForEach ($HKUSIDName in $HKUSIDNames)           
    { 
        $SID = $HKUSIDName
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        $User_Name = $objUser.Value 
        $HKUShareKey = $HKUrootkey.OpenSubKey($SID + "\Network")
        
        If($HKUShareKey -ne $Null)
        {
            $HKUShares = $HKUShareKey.GetSubKeyNames()
            ForEach($HKUShare in $HKUShares)
            {
                $HKUShareSet = $HKUShareKey.OpenSubKey($HKUShare)
                $RemotePath = $HKUShareSet.GetValue("RemotePath")
                $UserName = $HKUShareSet.GetValue("UserName")
                $Shares += $RemotePath + "|" + $UserName + "|" + $SID + "|" + $objUser
            }
        }
    }   
    #Close out Registry Connections
    $HKUShareSet.Close()
    #$HKUShareKey.Close()
    $HKUrootkey.Close()
    #Write out file
    $Shares | Out-File $Write_File -Append
    Write-Host "Done." -ForegroundColor Magenta

    echo "Got Remote Shares from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

Function Get_Netstat
{
    Param(
        $Computer
    )
    $Shares = @()
    Write-Host "Creating tcpview file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\tcpview.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\tcpview.txt"
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer tcpview...." -ForegroundColor Yellow
    cd $Script:Folder_Path\bin\
    .\psexec.exe \\$computer tcpvcon.exe -a -c >> $Script:Folder_Path\$Computer\tcpview.txt

    Write-Host "Done." -ForegroundColor Magenta

    echo "Got tcpview from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

Function Get_WMI_Event_Consumers
{
    Param(
        $Computer
    )
    Write-Host "Creating WMI Consumers file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\WMI_Event_Subsctiptions_Filter.txt" | Out-Null
    $Write_File_Filter = "$Script:Folder_Path\$computer\WMI_Event_Subsctiptions_Filter.txt"
    New-Item -type file -force "$Script:Folder_Path\$computer\WMI_Event_Subsctiptions_Consumer.txt" | Out-Null
    $Write_File_Consumer = "$Script:Folder_Path\$computer\WMI_Event_Subsctiptions_Consumer.txt"
    New-Item -type file -force "$Script:Folder_Path\$computer\WMI_Event_Subsctiptions_Binding.txt" | Out-Null
    $Write_File_Binding = "$Script:Folder_Path\$computer\WMI_Event_Subsctiptions_Binding.txt"
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer WMI Consumers...." -ForegroundColor Yellow

    Get-WMIObject -Namespace root\Subscription -Class __EventFilter -ComputerName $Computer | Select Name,QueryLanguage,Query | ConvertTo-Csv -Delimiter "|" -NoTypeInformation | % {$_.Replace('"','')} | Out-File $Write_File_Filter -Append
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ComputerName $Computer | Select Name,SourceName,UNCServerName | ConvertTo-Csv -Delimiter "|" -NoTypeInformation | % {$_.Replace('"','')} | Out-File $Write_File_Consumer -Append
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -ComputerName $Computer | Select Consumer,Filter | ConvertTo-Csv -Delimiter "|" -NoTypeInformation | % {$_.Replace('"','')} | Out-File $Write_File_Binding -Append
    Write-Host "Done." -ForegroundColor Magenta

    echo "Got WMI Consumers from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

Function Get_NetConfig
{
    Param(
        $Computer
    )
    Write-Host "Creating NetConfig file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\NetConfig.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\NetConfig.txt"
    Write-Host "Done." -ForegroundColor Magenta
    
    $output = @()
    Write-Host "Getting $Computer NetConfig...." -ForegroundColor Yellow
    Get-WmiObject -cl "Win32_NetworkAdapterConfiguration" -name "root\CimV2" -Impersonation 3 -ComputerName $Computer -filter "IpEnabled = TRUE" `
        | Select * | Out-File $Write_File -Append
    Write-Host "Done." -ForegroundColor Magenta

    echo "Got NetConfig from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

Function Get_Autoruns
{
    Param(
        $Computer
    )
    Write-Host "Creating AutoRuns file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\AutoRuns.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\AutoRuns.txt"
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer AutoRuns...." -ForegroundColor Yellow
    cd $Script:Folder_Path\bin\
    .\psexec.exe \\$Computer autorunsc.exe -accepteula -a * -c -h -s -t * >> $Script:Folder_Path\$Computer\autoruns.txt

    Write-Host "Done." -ForegroundColor Magenta

    echo "Got AutoRuns from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

Function Get_SigCheck
{
    Param(
        $Computer
    )
    Write-Host "Creating sigcheck file..." -ForegroundColor Green
    New-Item -type file -force "$Script:Folder_Path\$computer\sigcheck.txt" | Out-Null
    $Write_File = "$Script:Folder_Path\$computer\sigcheck.txt"
    Write-Host "Done." -ForegroundColor Magenta

    Write-Host "Getting $Computer sigcheck...." -ForegroundColor Yellow
    cd $Script:Folder_Path\bin\
    .\psexec.exe \\$Computer sigcheck -accepteula -u -c -s -e c:\windows >> $Script:Folder_Path\$Computer\sigcheck.txt

    Write-Host "Done." -ForegroundColor Magenta

    echo "Got sigcheck from $Computer" | out-file $Script:Log_File -Append
    echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append
}

# ========================================================================
# Jons_Code will look for the files
# ========================================================================
Function whats_the_process
{
    param(
        [string]$source,
        [array]$array,
        [int]$resp
    )
    
    New-Item -type file -force "$Script:Folder_Path\Bad_Computers_$Script:curDate.txt" | Out-Null
    $Script:Bad_Computers_File_Log = "$Script:Folder_Path\Bad_Computers_$Script:curDate.txt"
    $Script:Total_Bad_Computers = 0
    
    $i = 0
    ForEach ($Computer in $Script:Computers)
    {
        #Starts stopwatch for each computer check
        $Time = [System.Diagnostics.Stopwatch]::StartNew()
        $ping = ""
        echo "#######################################################" | Out-File $Script:Log_File -Append
        echo "###   Now Checking.... $Computer   ###" | Out-File $Script:Log_File -Append
        echo "#######################################################" | Out-File $Script:Log_File -Append
        # ========================================================================
        # Pinging the machine. If pass check for admin share access
        # ========================================================================
        $i++     
        $remaining = $computers.count - $i
        $total = $Computers.count
        write-progress -id 1 -Activity "Whats_The_Process is pulling processes from systems..." -Status "Searched $i systems out of $total... Currently on $Computer" -PercentComplete ($i / $Script:Computers.count * 100)
        
        $ping = Test-Connection -CN $Computer -Count 1 -BufferSize 16 -Quiet

        If ($ping -match 'True') 
        {
            echo "************************************************" | Out-File $Script:Log_File -Append
            echo "$Computer - ping was successful." | Out-File $Script:Log_File -Append

            Write-Host "Creating $Computer storage folder..." -ForegroundColor Green
            New-Item -type Directory -force "$Script:Folder_Path\$computer" | Out-Null
            Write-Host "Done." -ForegroundColor Magenta


            Get_Processes $Computer
            Get_Services $Computer
            Get_Drives $Computer
            Get_Tasks $Computer
            #Get_Netstat $Computer
            Get_Shares $Computer
            Get_WMI_Event_Consumers $Computer
            #Get_Networks $Computer
            Get_NetConfig $Computer
            #Get_Autoruns $Computer
            #Get_SigCheck $Computer


        }
        else 
        {
            . No_Ping $Computer $Script:Bad_Computers_File_Log
            $Script:Total_Bad_Computers = $Script:Total_Bad_Computers + 1
        }
        # Ends stopwatch per system and adds to Total Time Array
        $time.stop()
        $totalTime += $time.elapsed.seconds
    }
}
# ========================================================================
# Function Name 'Test-Administrator' - Checks if ran as admin
# ========================================================================
function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}


# ==============================================================================================
# Script Body - This is where the beginning magic happens
# ==============================================================================================
$erroractionpreference = "Continue"
# This tests to see if the user is an administrator, if not script attempts to runas the script.
If ((Test-Administrator) -ne $True)
{
    Write-Host "You are not an administrator" -Fore Red
    $Invocation = (Get-Variable MyInvocation).Value
    $Argument = (Split-Path $Invocation.MyCommand.Path) + "\" + ($invocation.mycommand.name)
    if ($Argument -ne "") 
    {   
        $arg = "-file `"$($Argument)`"" 
        Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arg -ErrorAction 'stop'  
    }
    exit # Quit this session of powershell  
}


Write-Host "Please select the location to store the files." -ForegroundColor Green
. Get_Folder_Path
echo "Got folder path... Next task..." | Out-File $Script:Log_File -Append
echo " " | Out-File $Script:Log_File -Append


Write-Host " "
Write-Host "How do you want to list computers?"	-ForegroundColor Green
$strResponse = Read-Host "`n[1] All Domain Computers (Must provide Domain), `n[2] Computer names from a File, `n[3] List a SingleComputer manually"
If($strResponse -eq "1"){. ListComputers | Sort-Object}
	elseif($strResponse -eq "2"){. ListTextFile}
	elseif($strResponse -eq "3"){. SingleEntry}
	else{Write-Host "You did not supply a correct response, `
	Please run script again."; pause -foregroundColor Red}				

echo "Got computer list... Next task..." | Out-File $Script:Log_File -Append
echo " " | Out-File $Script:Log_File -Append
. Whats_The_Process

echo "" | Out-File $Script:Log_File -Append 
echo "Script Complete...$((Get-Date).ToString("yyyy_MMM_dd-HH.mm.ss-tt"))" | Out-File $Script:Log_File -Append
echo "--------------------------------------------------------------" | out-file $Script:Log_File -Append 
echo " " | Out-File $Script:Log_File -Append