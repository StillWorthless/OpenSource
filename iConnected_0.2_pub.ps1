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
        write-host "iConnected will write all files to: $Script:Folder_Path"
        If(!(Test-Path "$Script:Folder_Path\iConnected_Log_File_$Script:curDate.txt"))
        {
            New-Item -type file -force "$Script:Folder_Path\iConnected_Log_File_$Script:curDate.txt" | Out-Null
        }
        $Script:Log_File = "$Script:Folder_Path\iConnected_Log_File_$Script:curDate.txt"
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
# iConnected - Logs all networks and checks last write time
# ========================================================================
Function iWirelessed
{
    


}


# ========================================================================
# iConnected - Logs all networks and checks last write time
# ========================================================================
Function iConnected
{ 
    New-Item -type file -force "$Script:Folder_Path\Bad_Computers_$Script:curDate.txt" | Out-Null
    $Script:Bad_Computers_File_Log = "$Script:Folder_Path\Bad_Computers_$Script:curDate.txt"
    $Script:Total_Bad_Computers = 0
    $totalTime = @()
    $htmlOutput = @()
    #echo "Checking for users in HKU ..." | out-file $Script:Log_File -Append
    #echo " " | out-file $Script:Log_File -Append
    $i = 0

    ForEach ($Computer in $Script:Computers)
    {
        
        #$newSystem = $False
        #$newuserInfo = $False
        #$newsysInfo = $False

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
        $avg = ($totaltime | Measure-Object -Average).average     
        $remaining = $computers.count - $i
        $total = $Computers.count
        $s = $avg * $remaining
        write-progress -id 1 -Activity "iConnected is running..." -Status "Time Remaining..." -SecondsRemaining $s
        write-progress -id 2 -parentId 1 -Activity "Searching through systems..." -Status "Searched $i systems out of $total..." -PercentComplete ($i / $Script:Computers.count * 100)
        
        $ping = Test-Connection -CN $Computer -Count 1 -BufferSize 16 -Quiet

        If ($ping -match 'True') 
        {
            echo "************************************************" | Out-File $Script:Log_File -Append
            echo "$Computer - ping was successful." | Out-File $Script:Log_File -Append
            
            $Script:System_Data = $False 
 
            # pull all network cards and link each one to Intranet domains 
            # that link to managed/unmanaged that link to profile GUIDs
            # that link to wireless adapters or lan adapters
            $Script:root = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($Script:HKLMroot, $Computer)
            if(-not $Script:root) { Write-Error "Can't open $($Script:HKLMroot) on $computer" }
            # key to network cards
            $KeyObj = $Script:root.OpenSubKey($Script:Network_Card_Key)
            if(-not $KeyObj) { Write-Error "Can't open $($Script:HKLMroot) on $computer" }
			# get sub key names
            $keys = $keyobj.GetSubKeyNames()
            #write-host $keys
            # rotate through each key
                echo "###########################################################" | Out-File $Write_File -Append
                echo "-----------------------------------------------------------" | Out-File $Write_File -Append
                echo "###########################################################" | Out-File $Write_File -Append
                echo " " | Out-File $Write_File -Append
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

                echo $NetworkCardDescription | Out-File $Write_File -Append
                echo $NetworkCardServiceName | Out-File $Write_File -Append
                echo "---------------------------------------" | Out-File $Write_File -Append

                # now that we have the network card info we open and list the intranets
                # using the networkcard servicename we can determine what network card connected to what intranet.
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
                                echo "$IntranetName - domain was accessed using: $NetworkCardDescription" | Out-File $Write_File -Append
                            }
                        }
                    }
                }
                Echo " " | Out-File $Write_File -Append
                Echo "###########################################################" | Out-File $Write_File -Append
                Echo "-----------------------------------------------------------" | Out-File $Write_File -Append
                Echo "###########################################################" | Out-File $Write_File -Append
                echo " " | Out-File $Write_File -Append
            }        
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

                            Echo "$ManUnManDNSSuffix - is the dns domain name of this network." | Out-File $Write_File -Append
                            Echo "$ManUnManFirstNetwork - this is the network name" | Out-File $Write_File -Append
                            Echo "$ManUnManDescription - This is the network description, typically matches the network name." | Out-File $Write_File -Append
                            Echo "MAC Address connected to was: "$($ManUnManMAC -join ("-")) | Out-File $Write_File -Append
                            Echo "$ManUnManProfGuid - Profile GUID. Will be used to get further information." | Out-File $Write_File -Append

                            # finally take the profile guid and get the datecreated and datelastconnected - convert the dates to strings
                            # grab description and profilename
                            $ProfileGuidkeys = $Script:root.OpenSubKey($Script:Profiles)
                            if(-not $ProfileGuidkeys) { Write-Error "Can't open profile keys on $computer" }
                            #$ProfileGuidkeyNames = $ProfileGuidkeys.GetSubKeyNames()
                            #if(-not $ProfileGuidkeyNames) { Write-Error "Can't list profile keys on $computer" }

                            #ForEach ($ProfileGuidkeyName in $ProfileGuidkeyNames)
                            #{
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

                                    Echo "$Script:ProfDateCreated - The date the first time connected" | Out-File $Write_File -Append
                                    Echo "$Script:ProfDateLastConnected - The date for the last time connected to the network" | Out-File $Write_File -Append
                                    Echo "$Script:ProfName - Another profile name, typically matches the network name" | Out-File $Write_File -Append
                                    Echo "$Script:ProfDesc - Another profile description, typically matches the network description" | Out-File $Write_File -Append
                                    Echo " " | Out-File $Write_File -Append
                                    
                                    # need to take the MAC and compare it to the OUI database
                                    

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
                                            Echo "WIRELESS CONNECTION DISCOVERED" | Out-File $Write_File -Append
                                            $CurWifiKey = $Wifi_Key.OpenSubKey($WifiKey)
                                            $SSIDS = $CurWifiKey.GetValueNames()
                                            ForEach ($SSID in $SSIDS)
                                            {
                                                $curSSID = @()
                                                If ($SSID -ne "Default")
                                                {
                                                    $splitssid = ([regex]::matches($SSID, '.{1,2}') | %{$_.value}) -join ' '
                                                    $splitssid.Split(' ') | FOREACH {$curSSID += ( [CHAR][BYTE]([CONVERT]::toint16($_,16)))}
                                                    $ActSSID = $curSSID -join ('')
                                                    If ($ActSSID -ne $Null,"")
                                                    {
                                                        Echo "The wireless network had this SSID: $ActSSID" | Out-File $Write_File -Append
                                                    }
                                                }

                                            }
                                        }

                                    }
                                    Echo "----------------------------------------------------------" | Out-File $Write_File -Append
                                    Echo "----------------------------------------------------------" | Out-File $Write_File -Append
                        }
                    }
            }
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