<#
    .SYNOPSIS  
        Locates all the current and past networks the computer has connected to, also provides last write time to show when it was plugged in.
        Displays as dns domain the machine connected to. 

    .DESCRIPTION  
          

    .NOTES  
        File Name      : iConnected.ps1
        Version        : v.0.2  
        Author         : StillWorthless
        Prerequisite   : PowerShell
        Created        : 12 MAY 13
     
     .CHANGELOG
        Update         : DATE
            Changes:   : 

     .TODO
        1. 

    ####################################################################################


#>
# Set Variables
# List of Registry Hives
$Script:HKUroot = [Microsoft.Win32.RegistryHive]::Users
$Script:HKLMroot = [Microsoft.Win32.RegistryHive]::LocalMachine
$Script:HKCUroot = [Microsoft.Win32.RegistryHive]::CurrentUsers
$Script:HKCRroot = [Microsoft.Win32.RegistryHive]::ClassesRoot
$Script:HKCCroot = [Microsoft.Win32.RegistryHive]::CurrentConfig
$Script:HKLM = "HKLM"
$Script:HKU = "HKU"
$Script:HKCU = "HKCU"
$Script:HKCR = "HKCR"
$Script:HKCC = "HKCC"

# HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\NetworkList

#List of DNSSuffix linked to connected networks
$Script:RegistryKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures"
$Script:IntranetKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Cache\Intranet"
$Script:DNSSuffix = "DnsSuffix"
$Script:FirstNetwork = "FirstNetwork"
$Script:Description = "Description"
$Script:MAC = "DefaultGatewayMac"
$Script:ProfGUID = "ProfileGuid"

#List of profiles created by connected networks
$Script:Profiles = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
$Script:DateCreated = "DateCreated"
$Script:DateLastConnected = "DateLastConnected"
$Script:ProfileName = "ProfileName"

# List of system info keys
$Script:Network_Card_Key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards"
$Script:Service_Key = "SYSTEM\CurrentControlSet\services"
$Script:Name_Key = "SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces"
$Script:NetCard_Desc = "Description"
$Script:NetCard_ServName = "ServiceName"

# List all wireless keys
$Script:Wireless_Key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Wireless"

$Script:curDate = ""
$Script:curDate = $((Get-Date).ToString("yyyy_MMM_dd-HH.mm.ss-tt")) ##Sets the date and time##
$Global:FinalItemsFound = @()

$netsubkeys = @()

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
                    #$curLogFile = $Script:Folder_Path + '\Results' + $Computer + '_' + $Script:curDate + '.txt'
        $Script:FindingsFolder = $Script:Folder_Path + "\Results"
        If ((Test-Path $Script:FindingsFolder) -ne $True) { New-Item -type Directory -Force $Script:FindingsFolder | Out-Null}
                        #If ((Test-Path $curLogFile) -ne $True) { New-Item -type file -force $curLogFile | Out-Null }
        write-host "iConnected will write all files to: $Script:Folder_Path\Results"
        If(!(Test-Path "$Script:Folder_Path\Results\iConnected_Log_File_$Script:curDate.txt"))
        {
            New-Item -type file -force "$Script:Folder_Path\Results\iConnected_Log_File_$Script:curDate.txt" | Out-Null
        }
        $Script:Log_File = "$Script:Folder_Path\Results\iConnected_Log_File_$Script:curDate.txt"
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

            $Script:Domain = Read-Host "Enter your Domain here: OU=users,DC=company,DC=com"
        #>
        
        # EDITABLE SECTION START
        Write-Host "Select 0 to enter your own domain entry."
        $response = Read-Host = "`n[0] Manual Entry"
        if($response -eq 0){$Script:Domain = Read-Host "Enter your Domain here: OU=users,DC=company,DC=com"}
        else {Write-Host "You did not provide a valid response."; . ListComputers}
        # EDITABLE SECTION END

        echo "Pulled computers from: "$Script:Domain | Out-File $Script:Log_File -Append
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
# Create a text file and enter the names of each computer. One computer
# name per line. Supply the path to the text file when prompted.
# ========================================================================
Function ListTextFile 
{
	$file_Dialog = ""
    $file_Name = ""
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $file_Dialog = New-Object system.windows.forms.openfiledialog
    $file_Dialog.InitialDirectory = "$env:USERPROFILE\Desktop"
    $file_Dialog.MultiSelect = $false
    $file_Dialog.showdialog()
    $file_Name = $file_Dialog.filename
    $Script:Computers = Get-Content $file_Name
    If ($Script:Computers -eq $Null) {
        Write-Host "Your file was empty. You must select a file with at least one computer in it." -Fore Red
        . ListTextFile }
    else {
        echo " " | Out-File $Script:Log_File -Append
        echo "Computer list located: $file_Name" | Out-File $Script:Log_File -Append }
}
# ========================================================================
# Function Name 'SingleEntry' - Enumerates Computer from user input
# ========================================================================
Function SingleEntry 
{
    $Script:Computers = Read-Host "Enter Computer Name or IP"
    If ($Script:Computers -eq $Null) { . SingleEntry } 
}

# ========================================================================
# Check Name 'No_Ping' - Logs when a system is unreachable by ping
# ========================================================================
Function No_Ping ($Computer, $Bad_Comp_File_Ping)
{
    echo $Computer | Out-File $Bad_Comp_File_Ping -Append
    echo "=======================================================================" | Out-File $Script:Log_File -Append
    echo "$Computer - was unreachable by PING" | Out-File $Script:Log_File -Append
    echo "=======================================================================" | Out-File $Script:Log_File -Append
}				
Function GetBinDate ($bin)
{
    $Script:FullDate = ""

    $hexvalues = $bin | foreach { [system.BitConverter]::ToString($_)} 

    $year = [Convert]::ToInt32($hexvalues[1] + $hexvalues[0],16)
    $Month = [Convert]::ToInt32($hexvalues[3] + $hexvalues[2],16)
    $WeekDay = [Convert]::ToInt32($hexvalues[5] + $hexvalues[4],16)
    $Date = [Convert]::ToInt32($hexvalues[7] + $hexvalues[6],16)
    $Hour = [Convert]::ToInt32($hexvalues[9] + $hexvalues[8],16)
    $Minute = [Convert]::ToInt32($hexvalues[11] + $hexvalues[10],16)
    $Second = [Convert]::ToInt32($hexvalues[13] + $hexvalues[12],16)

    switch ( $Month )
    {
        "1" { $MonthName = "January" }
        "2" { $MonthName = "February" }
        "3" { $MonthName = "March" }
        "4" { $MonthName = "April" }
        "5" { $MonthName = "May" }
        "6" { $MonthName = "June" }
        "7" { $MonthName = "July" }
        "8" { $MonthName = "August" }
        "9" { $MonthName = "September" }
        "10" { $MonthName = "October" }
        "11" { $MonthName = "November" }
        "12" { $MonthName = "December" }
        Default {  }
    }

    switch ( $WeekDay )
    {
        "0" { $WeekDayName = "Sunday" }
        "1" { $WeekDayName = "Monday" }
        "2" { $WeekDayName = "Tuesday" }
        "3" { $WeekDayName = "Wednesday" }
        "4" { $WeekDayName = "Thursday" }
        "5" { $WeekDayName = "Friday" }
        "6" { $WeekDayName = "Saturday" }
        Default {  }
    }
 
    $Script:FullDate = $WeekDayname + ", " + $date + " " + $MonthName + ", " + $year + " " + $Hour + ":" + $Minute + ":" + $Second

}
# ========================================================================
# Function Name 'System_Info' - Gathers System Information on a finding
# ========================================================================
Function System_Info ($Computer, $curLogFile)
{
    If ($Script:System_Data -ne $True)
    {
        echo "System Information....." | Out-File $curLogFile -Append
        #Collecting the IP Address of the system
        $colItems = GWMI -cl "Win32_NetworkAdapterConfiguration" -name "root\CimV2" -Impersonation 3 -ComputerName $Computer -filter "IpEnabled = TRUE"
        $actualIP = [System.Net.Dns]::GetHostAddresses("$computer") | foreach {if ($_.IPAddressToString -notmatch ":") {echo $_.IPAddressToString} }
        If (($colItems -ne $Null) -and ($colItems -ne ""))
        {                                
            ForEach ($objItem in $colItems)
            {
                if ($actualIP -eq $objItem.IpAddress)
                {
                    $ip = $objItem.IpAddress
                    $sub = $objItem.IPSubnet
                    $dfgw = $objItem.DefaultIPGateway
                    $dns = $objItem.DNSServerSearchOrder
                    $mac = $objItem.MACAddress
                    $dhcp = $objItem.DHCPEnabled

                    #========================================================#
                    #Testing for new HTML Output
                    #========================================================#
                    $htmlOutput += "<h2>System Information</h2>"
                    $htmlOutput += "<table>"
                    $htmlOutput += "<tr><td>IP Address----------:</td><td>$ip</td></tr>"
                    $htmlOutput += "<tr><td>Subnet--------------:</td><td>$sub</td></tr>"
                    $htmlOutput += "<tr><td>Default Gateway-----:</td><td>$dfgw</td></tr>"
                    $htmlOutput += "<tr><td>DNS Servers---------:</td><td>$dns</td></tr>"
                    $htmlOutput += "<tr><td>MAC Address---------:</td><td>$mac</td></tr>"
                    $htmlOutput += "<tr><td>DHCP Enabled--------:</td><td>$dhcp</td></tr>"
                    $htmlOutput += "</table>"

                    #========================================================#
                    #Testing for new HTML Output
                    #========================================================#
                    # Write to log file
                    echo "IP Address is: $ip" | Out-File $curLogFile -Append
                    echo "Subnet is: $sub" | Out-File $curLogFile -Append
                    echo "Default Gateway is: $dfgw" | Out-File $curLogFile -Append
                    echo "DNS Servers are: $dns" | Out-File $curLogFile -Append
                    echo "MAC Address is: $mac" | Out-File $curLogFile -Append
                    echo "Is DHCP Enabled: $dhcp" | Out-File $curLogFile -Append
                    echo "=======================================================================" | Out-File $curLogFile -Append
                    echo "=======================================================================" | Out-File $curLogFile -Append
                    echo " " | Out-File $curLogFile -Append
                    echo " " | Out-File $curLogFile -Append
                }
            }
        }
        else
        {
            #If WMI does not work report it to the log file and then get registry entries for the needed information.
            echo "WMI did not work on $computer. Grabbing information from the registry." | Out_File $curLogFile -Append
            #opens remote system base key (HKLM or HKU etc)
            #$rootkey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Script:HKLMroot, $Computer)
            # opens a key under root key
            # Opens the network card key to gather all network cards
            $NetworkCardKey = $Script:HKLMrootKey.OpenSubKey($Network_Card_Key)
            #Gets all keys under rootkey
            # Gets the names of all network cards
            $NetworkCardNameKeys = $NetworkCardKey.GetSubKeyNames()
            Foreach ($networkCard in $NetworkCardNameKeys)
            {
                $NetworkCard = $NetworkCardKey.OpenSubKey($networkCard)
                # gets value of the ServiceName for that networkcard
                $NeworkCardServiceName = $NetworkCard.GetValue("ServiceName")
                #Define variable for the Tcpip key
                $Service_Network_Key = $Service_Key + "\" + $NeworkCardServiceName + "\Parameters\Tcpip"
                # Open the subkey to the interface
                $Network_Info = $rootkey.OpenSubKey($Service_Network_Key)
                If ($Network_Info -ne $Null) {
                    # Get information about each tcpip parameter
                    $ipaddresses = $Network_Info.GetValue("IPAddress")
                    If (($ipaddresses -ne $Null) -and ($ipaddresses -ne "")) {        
                        if ($actualIP -eq $ipaddresses) {
                            echo "IP Address is: $ip" | Out-File $curLogFile -Append
                            $Subnets = $Network_Info.GetValue("Subnet")
                            If (($Subnets -ne $Null) -and ($Subnets -ne "")) { 
                                foreach ($Sub in $Subnets) { echo "Subnet is: $sub" | Out-File $curLogFile -Append } }
                            $DefaultGateways = $Network_Info.GetValue("DefaultGateway")
                            If (($DefaultGateways -ne $Null) -and ($DefaultGateways -ne "")) { 
                                foreach ($dfgw in $DefaultGateways) { echo "Default Gateway is: $dfgw" | Out-File $curLogFile -Append } }
                            $dhcp = $Network_Info.GetValue("EnableDHCP")
                            If ($dhcp -eq 1) { echo "Is DHCP Enabled: $True" | Out-File $curLogFile -Append }
                            elseif ($dhcp -eq 0) { echo "Is DHCP Enabled: $False" | Out-File $curLogFile -Append } }

                        $NameServerKey = $Name_Key + "\" + $NeworkCardServiceName
                        $NameServer_Key = $rootkey.OpenSubKey($NameServerKey)
                
                        If ($NameServer_Key -ne $Null) {
                            $NameServer = $NameServer_Key.GetValue("NameServer")
                            If (($NameServer -ne "") -and ($NameServer -ne $Null)) { 
                                foreach ($dns in $NameServer) { echo "DNS Servers are: "$dns | Out-File $curLogFile -Append } } }
                        echo "=======================================================================" | Out-File $curLogFile -Append
                        echo "=======================================================================" | Out-File $curLogFile -Append
                        echo " " | Out-File $curLogFile -Append
                        echo " " | Out-File $curLogFile -Append

                        #========================================================#
                        #Testing for new HTML Output
                        #========================================================#
                        $htmlOutput += "<h2>System Information</h2>"
                        $htmlOutput += "<table>"
                        $htmlOutput += "<tr><td>IP Address----------:</td><td>$ip</td></tr>"
                        $htmlOutput += "<tr><td>Subnet--------------:</td><td>$sub</td></tr>"
                        $htmlOutput += "<tr><td>Default Gateway-----:</td><td>$dfgw</td></tr>"
                        $htmlOutput += "<tr><td>DNS Servers---------:</td><td>$dns</td></tr>"
                        $htmlOutput += "<tr><td>MAC Address---------:</td><td>N/A</td></tr>"
                        $htmlOutput += "<tr><td>DHCP Enabled--------:</td><td>$dhcp</td></tr>"
                        $htmlOutput += "</table>"

                        #========================================================#
                        #Testing for new HTML Output
                        #========================================================#
                    }
                }
                $Network_Info.Close()
                $NameServer_Key.Close()
                $NetworkCard.Close()
            }
            $NetworkCardKey.Close()
        }
        $Script:System_Data = $True
    }
}

# ========================================================================
# iConnected - Logs all networks and checks last write time
# ========================================================================
Function iConnected
{ 
    New-Item -type file -force "$Script:Folder_Path\iConnected_Bad_Computers_$Script:curDate.txt" | Out-Null
    $Script:Bad_Computers_File_Log = "$Script:Folder_Path\iConnected_Bad_Computers_$Script:curDate.txt"
    $Script:Total_Bad_Computers = 0
    $totalTime = @()
    $htmlOutput = @()
    $newRun = $False
    $i = 0
    #========================================================#
    #Testing for new output
    #========================================================#
    If ($newRun -ne $True) {
        $htmlOutput += "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Strict//EN'  'http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd'>"
        $htmlOutput += "<html xmlns='http://www.w3.org/1999/xhtml'>"
        $htmlOutput += "<head>"
        $htmlOutput += "<title>iConnected</title>"
        $htmlOutput += "</head><body>"
        $htmlOutput += "<h1>iConnected Report</h1>"
        $htmlOutput += "<h3>Report Generated on $(Get-Date)</h3>"
        $newRun = $True
    }

    If ($newuserInfo -ne $True) { [void]$Script:newcomputer.AppendChild($Script:newcomputerUserinfo); $newuserInfo = $True }
    If ($AppendedUser -ne $True) { [void]$Script:newcomputerUserinfo.AppendChild($Script:newcomputerUser); $AppendedUser = $True; 
        
    }
    ForEach ($Computer in $Script:Computers)
    {
        
        $newSystem = $False
        $newsysInfo = $False
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
        write-progress -id 1 -Activity "Searching through systems..." -Status "Searched $i systems out of $total..." -PercentComplete ($i / $Script:Computers.count * 100)
        
        $ping = Test-Connection -CN $Computer -Count 1 -BufferSize 16 -Quiet

        If ($ping -match 'True') 
        {
            echo "************************************************" | Out-File $Script:Log_File -Append
            echo "$Computer - ping was successful." | Out-File $Script:Log_File -Append
            $Script:System_Data = $False 
            $Script:root = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Script:HKLMroot, $Computer)
            if(-not $Script:root) { Write-Error "Can't open $($Script:HKLMroot) on $computer" }
            $KeyObj = $Script:root.OpenSubKey($Script:Network_Card_Key)
            if(-not $KeyObj) { Write-Error "Can't open $($Script:HKLMroot) on $computer" }
            $keys = $keyobj.GetSubKeyNames()
            If ($Keys -ne $Null)
            {
                If ($newSystem -ne $True) 
                { 
                    $newSystem = $True
                    $htmlOutput += "<table>"
                    $htmlOutput += "<h1>$Computer</h1>"
                    $htmlOutput += "</table>"
                    . System_Info $Computer $curLogFile;
                    $htmlOutput += "<h2>Network Devices</h2>"
                    #$htmlOutput += "<h2>USB Information</h2>"
                }
            }
            foreach ($key in $keys)
            {
                # Opens each sub key or network card reg entry
                $subkeyopen = $keyobj.OpenSubKey($key)
                if(-not $subkeyopen) { Write-Error "Can't open $($Script:HKLMroot) on $computer" }
                $subkeys = $subkeyopen.GetValueNames()
                if(-not $subkeys) { Write-Error "Can't open $($Script:HKLMroot) on $computer" }
                # list each key value name in network card (looking or ServiceName and Description)
                $NetworkCardDescription = $subkeyopen.GetValue($Script:NetCard_Desc)
                $NetworkCardServiceName = $subkeyopen.GetValue($Script:NetCard_ServName)

                #========================================================#
                #Testing for new HTML Output
                #========================================================#
                $htmlOutput += "<table>"
                $htmlOutput += "<tr><td>Network Card Name---------:</td><td>$NetworkCardDescription</td></tr>"
                $htmlOutput += "<tr><td>Network Card GUID Name----:</td><td>$NetworkCardServiceName</td></tr>"
                #========================================================#
                #Testing for new HTML Output
                #========================================================#
                $KeyObj2 = $Script:root.OpenSubKey($Script:IntranetKey)
                if(-not $KeyObj2) { Write-Error "Can't open $($Script:HKLMroot) on $computer" }    
                # get sub key names
                $keys2 = $keyobj2.GetSubKeyNames()
                # rotate through each key
                foreach ($key2 in $keys2)
                {    
                    # Grabs the name of the intranet keyname
                    $IntranetName = $key2

                    # open the key and grab the profile GUIDs
                    $IntraSubKeyOpen = $KeyObj2.OpenSubKey($key2)
                     $subkeyValues = $IntraSubKeyOpen.GetValueNames()
                     if(-not $subkeyValues) { Write-Error "Can't open the intranet key on $computer" }
                    # list each key value name in network card (looking or ServiceName and Description)
                    Foreach ($subkeyvalue in $Subkeyvalues)
                    {
                        If ($subkeyvalue -ne "Failures","Successes","Default")
                        {
                            If ($subkeyvalue -eq $NetworkCardServiceName)
                            {
                                $htmlOutput += "<tr><td>Connected to Domain-------:</td><td>$IntranetName</td></tr>"
                            }
                        }
                    }
                    $htmlOutput += "<tr>--------------------------</tr>"
                }
                $htmlOutput += "<tr> </tr>"
            }    
            $htmlOutput += "</table>" 
            $htmlOutput += "<tr>========================================================================================</tr>" 
            
            
            $htmlOutput += "<h2>Networks</h2>"  
            # Take intranetname and find it in managed or unmanaged
            $ManUnmanKeys = $Script:root.OpenSubKey($Script:RegistryKey)
            if(-not $ManUnmanKeys) { Write-Error "Can't open Managed or Unmanaged keys on $computer" }
            $ManUnmankeyNames = $ManUnmanKeys.GetSubKeyNames()
            if(-not $ManUnmankeyNames) { Write-Error "Can't get Managed or Unmanaged key names on $computer" }
            ForEach ($ManUnmankeyName in $ManUnmankeyNames)
            {
                # Opens either Managed or Unmanaged
                $manUnmanSubKeys = $ManUnmankeys.OpenSubKey($ManUnmankeyName)
                if(-not $manUnmanSubKeys) { Write-Error "Can't get Managed or Unmanaged key on $computer" }
                # get the subkey names under either managed or unmanaged
                $manUnmanSubKeyNames = $manUnmanSubKeys.GetSubKeyNames()
                if(-not $manUnmanSubKeyNames) { Write-Error "Can't get Managed or Unmanaged key names on $computer" }
                # Get the values of the needed keys
                ForEach ($manUnmanSubKeyName in $manUnmanSubKeyNames)
                {
                    $OpenManUnManKey = $manUnmanSubKeys.OpenSubKey($manUnmanSubKeyName)
                    $ManUnManMAC = ""
                    $ManUnManDNSSuffix = $OpenManUnManKey.GetValue($Script:DNSSuffix)
                    $ManUnManFirstNetwork = $OpenManUnManKey.GetValue($Script:FirstNetwork)
                    $ManUnManDescription = $OpenManUnManKey.GetValue($Script:Description)
                    $ManUnManMAC = $($OpenManUnManKey.GetValue($Script:MAC)) | foreach { [system.BitConverter]::ToString($_)}
                    $ManUnManProfGuid = $OpenManUnManKey.GetValue($Script:ProfGUID)
                    #========================================================#
                    #Testing for new HTML Output
                    #========================================================#
                    $htmlOutput += "<table>"
                    $htmlOutput += "<tr>####################################################################</tr>"
                    $htmlOutput += "<tr><td>DNS Domain Name-----------:</td><td>$ManUnManDNSSuffix</td></tr>"
                    $htmlOutput += "<tr><td>Network Name--------------:</td><td>$ManUnManFirstNetwork</td></tr>"
                    $htmlOutput += "<tr><td>Network Description-------:</td><td>$ManUnManDescription</td></tr>"
                    $htmlOutput += "<tr><td>MAC Address---------------:</td><td>$($ManUnManMAC -join ("-"))</td></tr>"
                    #========================================================#
                    #Testing for new HTML Output
                    #========================================================#
                    $ProfileGuidkeys = $Script:root.OpenSubKey($Script:Profiles)
                    if(-not $ProfileGuidkeys) { Write-Error "Can't open profile keys on $computer" }
                    $profileOpenGuid = $ProfileGuidkeys.OpenSubKey($ManUnManProfGuid)
                    if(-not $profileOpenGuid) { Write-Error "Can't open profile key on $computer" }
                    $Script:ProfileDateCreated = $profileOpenGuid.GetValue($Script:DateCreated)
                    . GetBinDate $Script:ProfileDateCreated
                    $Script:ProfDateCreated = $Script:FullDate
                                    
                    $Script:ProfileDateLastConnected = $profileOpenGuid.GetValue($Script:DateLastConnected)
                    . GetBinDate $Script:ProfileDateLastConnected
                    $Script:ProfDateLastConnected = $Script:FullDate

                    $Script:ProfName = $profileOpenGuid.GetValue($Script:ProfileName)
                    $Script:ProfDesc = $profileOpenGuid.GetValue($Script:Description)
                    #========================================================#
                    #Testing for new HTML Output
                    #========================================================#
                    $htmlOutput += "<tr><td>FirstTimeConnected---------:</td><td>$Script:ProfDateCreated</td></tr>"
                    $htmlOutput += "<tr><td>LastTimeConnected----------:</td><td>$Script:ProfDateLastConnected</td></tr>"
                    $htmlOutput += "<tr><td>Profile Name---------------:</td><td>$Script:ProfName</td></tr>"
                    $htmlOutput += "<tr><td>Profile Description--------:</td><td>$Script:ProfDesc</td></tr>"
                    #========================================================#
                    #Testing for new HTML Output
                    #========================================================#
                    
                    ############
                    # Checking WIFI
                    ############
                    $keytoCheckWifi = $manUnmanSubKeyName.Substring(32)
                    #open wireless key
                    $Wifi_Key = $Script:root.OpenSubKey($Script:Wireless_Key)
                    if(-not $ProfileGuidkeys) { Write-Error "Can't open profile keys on $computer" }
                    #get subkeys wireless
                    $wifiKeys = $Wifi_Key.GetSubKeyNames()
                    #match keytocheckwifi for match
                    ForEach ($WifiKey in $WifiKeys)
                    {
                        If ($keytoCheckWifi -eq $WifiKey)
                        {
                            $CurWifiKey = $Wifi_Key.OpenSubKey($WifiKey)
                            $SSIDS = $CurWifiKey.GetValueNames()
                            ForEach ($SSID in $SSIDS)
                            {
                                $curSSID = @()
                                If ($SSID -ne "(Default)")
                                {
                                    $splitssid = ([regex]::matches($SSID, '.{1,2}') | %{$_.value}) -join ' '
                                    $splitssid.Split(' ') | FOREACH {$curSSID += ( [CHAR][BYTE]([CONVERT]::toint16($_,16)))}
                                    $ActSSID = $curSSID -join ('')
                                    If (($ActSSID -ne "") -and ($ActSSID -ne $Null))
                                    {
                                        $htmlOutput += "<tr><td>SSID-----------------------:</td><td>$ActSSID</td></tr>"
                                    }
                                }

                            }
                        }

                    }
                }
            }
        }
    }
    
    $htmlOutput += "</table>"
    #========================================================#
    #Testing for new output
    #========================================================#
    If ($htmlOutput -ne $Null)
    {
        $htmlOutput += "<table>"
        $htmlOutput += "<tr>========================================================================================</tr>"
        $htmlOutput += "</table>"
        $htmlOutput += "</body></head>"
        $Script:HtmlPath = $Script:Folder_Path + "\Results\Results_" + $Script:curDate + ".html"

        $htmlOutput | out-file $Script:HtmlPath; ii $Script:HtmlPath
    }
}
# ========================================================================
# Get_LastWriteTime_Reg connects via remote registry and pulls the last
# write time for the key that was sent as subkey
# ========================================================================
Function Get_LastWriteTime_Reg ($Computer, [string] $key, [string] $SubKey, [string] $Key_Time)
{
<#
    This function was taken from: 
    http://blog.securitywhole.com/2010/02/getting-registry-last-write-time-with_2641.html
    Written by Tim Medin
    Found: 27APR13
    
    I added the ability to connect to remote registry for the last write time.
#>
    switch ($Key) {
        "HKCR" { $searchKey = 0x80000000} #HK Classes Root
        "HKCU" { $searchKey = 0x80000001} #HK Current User
        "HKLM" { $searchKey = 0x80000002} #HK Local Machine
        "HKU"  { $searchKey = 0x80000003} #HK Users
        "HKCC" { $searchKey = 0x80000005} #HK Current Config
        default { 
            #throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
        }
    }
    $KEYQUERYVALUE = 0x1
    $KEYREAD = 0x19
    $KEYALLACCESS = 0x3F
    
    $sig0 = @'
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegConnectRegistry(
    string lpmachineName, 
    int hKey, 
    ref int phKResult);
'@
    $type0 = Add-Type -MemberDefinition $sig0 -Name Win32Utils `
        -Namespace RegConnectRegistry -Using System.Text -PassThru
    $sig1 = @'
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    public static extern int RegOpenKeyEx(
        int hKey,
        string subKey,
        int ulOptions,
        int samDesired,
        out int hkResult);
'@
    $type1 = Add-Type -MemberDefinition $sig1 -Name Win32Utils `
        -Namespace RegOpenKeyEx -Using System.Text -PassThru
    $sig2 = @'
    [DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
    extern public static int RegEnumKeyEx(
        int hkey,
        int index,
        StringBuilder lpName,
        ref int lpcbName,
        int reserved,
        int lpClass,
        int lpcbClass,
        out long lpftLastWriteTime);
'@
    $type2 = Add-Type -MemberDefinition $sig2 -Name Win32Utils `
        -Namespace RegEnumKeyEx -Using System.Text -PassThru
    $sig3 = @'
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern int RegCloseKey(
        int hKey); 
'@
    $type3 = Add-Type -MemberDefinition $sig3 -Name Win32Utils `
         -Namespace RegCloseKey -Using System.Text -PassThru

    $phKResult = New-Object IntPtr(0)
    $Comp_Name = "\\" + $Computer
    $result = $type0::RegConnectRegistry($Comp_Name,$searchKey,[ref] $phKResult)
    $hKey = new-object int
    $result = $type1::RegOpenKeyEx($phKResult, $SubKey, 0, $KEYREAD,[ref] $hKey)
    #initialize variables
    $builder = New-Object System.Text.StringBuilder 1024
    $index = 0
    $length = [int] 1024
    $time = New-Object Long
    #234 means more info, 0 means success. Either way, keep reading
    while ( 0,234 -contains $type2::RegEnumKeyEx($hKey, $index++, `
        $builder, [ref] $length, $null, $null, $null, [ref] $time) )
    {
        #create output object
        $tmp = $builder.ToString()
        if ($tmp -eq $Key_Time)
        {
            $o = "" | Select Key, LastWriteTime
            $o.Key = $builder.ToString()
            $o.LastWriteTime = (Get-Date $time).AddYears(1600)
            $o
        }
        #reinitialize for next time through the loop  
        $length = [int] 1024
        $builder = New-Object System.Text.StringBuilder 1024
    }
    $result = $type3::RegCloseKey($hKey);
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
# Lets create your powershell window environment
. Set-Wide

Write-Host "iConnected needs to know where to write the results to." -ForegroundColor Green
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

Write-Host "Creating iConnected file..." -ForegroundColor Green
New-Item -type file -force "$Script:Folder_Path\$computer\iConnected.txt" | Out-Null
$Write_File = "$Script:Folder_Path\$computer\iConnected.txt"
Write-Host "Done." -ForegroundColor Magenta

Write-Host "Getting $Computer iConnected...." -ForegroundColor Yellow
. iConnected

Write-Host "Done." -ForegroundColor Magenta

echo "Got iConnected from $Computer" | out-file $Script:Log_File -Append
echo "[][][][][][][][][][][][][][][][][][][][][][][][][]" | out-file $Script:Log_File -Append