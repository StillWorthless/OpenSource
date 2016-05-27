<#
    .SYNOPSIS  
        Takes an array of file names and searches a directory recursively and lists all matches in a results file. 

    .DESCRIPTION  
          

    .NOTES  
        File Name      : psFileFind.ps1
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

#########################################################
# Here is where you list the names of files you are looking
# for. Format: ('name.txt', 'nextname.pdf')
#
#########################################################
$Names = @( 'facebook-profile-pic-',
            'facebook-pic00',
            'skype_',
            'ozkqke.exe',
            'libssp-0.dll',
            'ctfmon.exe',
            'libssp-0.dll',
            'QTI International Inc',
            'CallTogether',
            'AdobeSetupx86.exe',
            'AdobeSetup32.sfx.exe',
            'horr2.jpg',
            'Google Update.exe',
            'flashplayer11x32_gdrd_aih.exe',
            'Microsoft-Update.exe',
            'Keys.txt',
            'Microsoft-Update.exe',
            'flashplayer11x32_gdrd_aih.exe',
            'idm-en-setup.exe',
            'IslamArmyThem.exe',
            'Keyboard-Sounds.exe',
            'Pdf-to-Word-Converter.exe',
            'from-aliwa2-doctor-salim-dris-to-whom-it-may-concern.exe',
            'diplaced-syrian-people-cod.exe',
            'Displaced-Syrians-Suffering_cod.exe',
            'install_flashplayer11x32_gdrd_aih.exe',
            'JetCleanSetup.exe',
            'Maktal-Kiyadi-Barez-men-hizbillah-fi-ltafgir-l2akhir-fi-ldahya12300012.exe',
            'AdobeReader-9-En-Us.exe',
            'Eye-Protector-Portial-Setup.exe',
            'Billiards.exe',
            'New-Iman-Picture.pif',
            'Live-Chat-ooVoo-Setup.exe',
            'nazhin.exe',
            'Video-Downloader.exe',
            'Amer-Mohemmeh.exe',
            'Russia-vs-Amerika.exe',
            'google-update.sfx.exe',
            'adobereadersetup-86x.sfx.exe',
            'adobeflash.sfx.exe',
            'oovoo-setup.sfx.exe',
            'microtec.sfx.exe',
            'Microsoft-Update.sfx.exe',
            'adobesetup.sfx.exe',
            'adobesetupx86.sfx.exe',
            'office-word-update.sfx.exe',
            'update-flashplayer11.sfx.exe',
            'adobereader-86x.sfx.exe',
            'adobesetup32.sfx.exe',
            'adobe32en.sfx.exe',
            'adobereader-86x-64x.sfx.exe',
            'adobred-86x.sfx.exe',
            'Syrian-Girl-Against-Regime',
            'Syrian-chlidren-under-execution',
            'adobereadersetup-86x.exe',
            'DIOKAK',
            'UXLNYL',
            'adobesetup.exe',
            'adobe32en.exe',
            'adobereadersetup-86x.exe',
            'adobex86setup.sfx.exe',
            'google-update.exe',
            'adobereader-86x.exe',
            'adobesetupx86.exe',
            'adobred-86x.exe',
            'adobereader-86x-64x.exe',
            'adobeflash.exe',
            'adobesetup32.exe',
            'adobeinsx86.exe',
            'adobesetupx86.exe',
            'microtec.exe',
            'DC_MUTEX',
            'greenhill.png',
            'reporthezbolla20072013_pdf.exe',
            'bayan09072013_pdf.exe',
            'Keyboard-Sounds.exe',
            'vpn7x32.exe',
            'GoogleUpdate.exe',
            'Yabrod.pdf',
            'Keyboard-Sounds.exe',
            'VPN7.exe',
            'Facebook-Account.exe',
            'ardws.exe',
            'rdws.exe',
            'tqPx.dll',
            'ACID',
            'netsvc.exe',
            'MicrosoftGMMExit',
            'MicrosoftGMMHaveExit',
            'MicrosoftGMMZJ',
            'CTFM0N.exe',
            'CTFM0N',
            'MicrosoftShipZJ',
            'MSDEV.EXE',
            'MicrosoftShipTrExit',
            'MicrosoftShipTrHaveExit',
            'MicrosoftShipTrZJ',
            'VFP6.EXE',
            'ldf',
            'MicrosoftFlashZJ',
            'MicrosoftFlashExit',
            'MicrosoftFlashHaveExit',
            'msinm.exe',
            'msinm.exe',
            'FILETIME.DAT',
            'wssfmgr.exe',
            'ccSvcHst.exe',
            'iexplore.exe',
            'SJZJ (compatible; MSIE 6.0; Win32)',
            'Neteagle_Scout',
            'Eagle-Norton360-OfficeScan',
            'WINWORD.exe',
            'MicrosoftZjZRLnkHaveExit',
            'MicrosoftZjSYNoReg',
            'MicrosoftSYNoRegExit',
            'MicrosoftSYNoRegHaveExit',
            'MicrosoftSYNoRegHaveAck',
            'MicrosoftZjZRLnk',
            'MicrosoftZjZRLnkExit',
            'msmsgs.exe',
            'doc.exe',
            'test.exe',
            'notepad1.exe',
            'notepad.exe',
            'newnotepad.exe',
            'notepad2.exe',
            'note.txt',
            'MShell.pdb',
            '4113.pdb',
            'Client.pdb',
            'Projects',
            'test.exe',
            '358bd08946',
            'PnP_No_Management',
            'libcurl-4.dll',
            'pthreadgc2.dll',
            'zlib1.dll',
            'syshost.exe',
            'autorun.inf',
            'WinUpdate.exe',
            'Zqfsfr.exe')

$DirWNames = @( "\AppData\Roaming\c731200",
                "\AppData\Roaming\ScreenSaverPro.scr",
                "\AppData\Roaming\temp.bin",
                "\AppData\Roaming\update\explorer.exe",
                "\AppData\Roaming\update\cleaner.exe",
                "\AppData\Roaming\update\update.exe",
                "\AppData\Roaming\windowsupdate\updater.exe",
                "\AppData\Roaming%\windowsupdate\live.exe",
                "\AppData\Roaming\Windows Live\",
                "\AppData\Local\Temp\Adobe\Reader_sl.exe",
                "\AppData\Local\Temp\c731200",
                "\AppData\Roaming\frameworkupdate7\chromeupdate.exe.",
                "\AppData\Roaming\vfbu.exe",
                "\AppData\Local\vfbu.exe",
                "\AppData\LocalLow\vfbu.exe",
                "\AppData\Local\Temp\windows\winsys.exe" )

$RegLocations = @( "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman\*vfbu.exe")

#########################################################
# Here is where you list the locations to search for
# files. Format: ('\\share\folder', '')
#
#########################################################
$Locations = @("\\$Computer\c$")



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


# ========================================================================
# Check_Users will look for the files
# ========================================================================
Function Check_Files
{
    param(
        [string]$source,
        [array]$array,
        [array]$array2
    )
    Write-Output "Starting Darkbot check...." | Out-File $Script:Log_File -Append
    If($array2 -ne $null)
    {
        $users = GCI "$source\Users"
        ForEach($user in $users)
        {
            $username = $user.Name
            ForEach ($DirWName in $array2)
            {
                $path = ""
                $path = $source + "\Users\" + $username + $DirWName
                Write-Host $path
                
                If(Test-Path -Path $path )
                {
                    If(!(Test-Path "$Script:Folder_Path\DarkBot_Report_$Script:curDate.txt"))
                    { 
                        New-Item -type file -force "$Script:Folder_Path\DarkBot_Report_$Script:curDate.txt" | Out-Null 
                        $DarkBotReport = "$Script:Folder_Path\DarkBot_Report_$Script:curDate.txt"
                    }
                    Write-Output $path | Out-File $DarkBotReport -Append
                    Write-Output "Darkbot found at: $path" | Out-File $Script:Log_File -Append

                    Write-Host "###########################################################" -Fore Magenta
                    Write-Host "-----------------------------------------------------------" -Fore Magenta
                    Write-Host $path -Fore Yellow
                    Write-Host "Username is: $userName" -Fore Yellow
                    Write-Host "DARKBOT FOUND.... $DirWName" -Fore Yellow
                    Write-Host "-----------------------------------------------------------" -Fore Magenta
                    Write-Host "###########################################################" -Fore Magenta
                }

            }
        }
    }
    $i = 0
    $x = 0
    Get-ChildItem -Path $source -Recurse -Force | 
        Where-Object { 
            ForEach($filename in $array)
            {
                If ($i -eq 10000)
                {
                    $x += $i
                    $i=0
                    Write-Output "==========================" | Out-File $Script:Log_File -Append 
                    Write-Output "10k hit at $($_.DirectoryName)" | Out-File $Script:Log_File -Append
                    Write-Output "==========================" | Out-File $Script:Log_File -Append
                    Write-Host "Files processed - $x" 
                }
                If($_.Name -like $filename)
                {
                    Write-Host "###########################################################" -Fore Red
                    Write-Host "-----------------------------------------------------------" -Fore Red
                    Write-Host $_.FullName -Fore Green
                    Write-Host "Matched on.... $fileName" -Fore Green
                    Write-Host "-----------------------------------------------------------" -Fore Red
                    Write-Host "###########################################################" -Fore Red

                    Write-Output $_.FullName | Out-File $Script:Results_File -Append
                    Write-Output "Matched on.... $fileName" | Out-File $Script:Log_File -Append
                    Write-Output "-----------------------------------------------------------" | Out-File $Script:Log_File -Append

                    Write-Output "File found: $($_.FullName)" | Out-File $Script:Log_File -Append
                    Write-Output "Matched on.... $fileName" | Out-File $Script:Log_File -Append
                    Write-Output "-----------------------------------------------------------" | Out-File $Script:Log_File -Append
                } #End If
            } #End ForEach
            $i++
        } #End Where-Object
}
# ========================================================================
# Function Name 'Test-Administrator' - Checks if ran as admin
# ========================================================================
function Test-Administrator  
{  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}
$erroractionpreference = "SilentlyContinue"
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

Write-Host "Do you want to list computers or only use locations?" -ForegroundColor Green
$strResponse1 = Read-Host "`n[1] Locations Only, `n[2] List Computers Only, `n[3] Locations and List Computers"
If($strResponse1 -eq 1)
{
    If($Locations -ne $Null)
    { 
        Write-Host "Starting psFileFind....." -ForegroundColor Yellow
        ForEach($Location in $Locations)
        {
            . Check_Files $Location $Names
        }
    }
}
elseif($strResponse1 -eq 2)
{
    Write-Host " "
    Write-Host "How do you want to list computers?"	-ForegroundColor Green
    $strResponse = Read-Host "`n[1] All Domain Computers (Must provide Domain), `n[2] Computer names from a File, `n[3] List a Single Computer manually"
    If($strResponse -eq "1"){. ListComputers | Sort-Object}
	    elseif($strResponse -eq "2"){. ListTextFile}
	    elseif($strResponse -eq "3"){. SingleEntry}
	    else{Write-Host "You did not supply a correct response, `
	    Please run script again."; pause -foregroundColor Red}

    echo "Got computer list... Next task..." | Out-File $Script:Log_File -Append
    echo " " | Out-File $Script:Log_File -Append
    
    If($Script:Computers -ne $Null)
    {
        Write-Host "Starting psFileFind....." -ForegroundColor Yellow
        ForEach($Computer in $Script:Computers)
        {
            $loc = "\\$computer\C$"; 
            . Check_Files $loc $Names $DirWNames
        } 
    } 
}
elseif($strResponse1 -eq 3)
{
    Write-Host " "
    Write-Host "How do you want to list computers?"	-ForegroundColor Green
    $strResponse = Read-Host "`n[1] All Domain Computers (Must provide Domain), `n[2] Computer names from a File, `n[3] List a Single Computer manually"
    If($strResponse -eq "1"){. ListComputers | Sort-Object}
	    elseif($strResponse -eq "2"){. ListTextFile}
	    elseif($strResponse -eq "3"){. SingleEntry}
	    else{Write-Host "You did not supply a correct response, `
	    Please run script again."; pause -foregroundColor Red}

    echo "Got computer list... Next task..." | Out-File $Script:Log_File -Append
    echo " " | Out-File $Script:Log_File -Append
    If($Locations -ne $Null)
    { 
        Write-Host "Starting psFileFind Locations....." -ForegroundColor Yellow
        ForEach($Location in $Locations)
        {
            . Check_Files $Location $Names
        }
    }
    If($Script:Computers -ne $Null)
    {
        Write-Host "Starting psFileFind Computers....." -ForegroundColor Yellow
        ForEach($Computer in $Script:Computers)
        {
                $loc = "\\$computer\C$"
                . Check_Files $loc $Names $DirWNames
        }
    }
}

echo "" | Out-File $Script:Log_File -Append 
echo "Script Complete...$((Get-Date).ToString("yyyy_MMM_dd-HH.mm.ss-tt"))" | Out-File $Script:Log_File -Append
echo "--------------------------------------------------------------" | out-file $Script:Log_File -Append 
echo " " | Out-File $Script:Log_File -Append