@ECHO OFF

netsh.exe wlan show profiles name=’Profile Name’ key=clear >> C:\folder\Wifi.txt
C:\folder\$Computer\tcpvcon.exe -accepteula -a -c >> C:\folder\$Computer\tcpview-netstat.txt
C:\folder\$Computer\autorunsc.exe -accepteula -a * -c -h -s -t * >> C:\folder\$Computer\autoruns.txt
C:\folder\$Computer\sigcheck.exe -accepteula -u -c -s -e c:\windows >> C:\folder\$Computer\sigcheck.txt


