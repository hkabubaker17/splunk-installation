function Get-Splunk(){

    #Download and install UF
    $uri = "https://download.splunk.com/products/universalforwarder/releases/9.0.1/windows/splunkforwarder-9.0.1-82c987350fde-x64-release.msi"
    $out = "C:\Users\Public\Downloads\splunkforwarder.msi"
    Invoke-WebRequest -uri $uri -OutFile $out
    msiexec.exe /i $out AGREETOLICENSE=1 SPLUNKUSERNAME=admin SPLUNKPASSWORD=mypassword /qb /l*v install.log
}
function Config-Splunk{

    #Edit config files
    echo "[deployment-client]`n`n[target-broker:deploymentServer]`ntargetUri = $($Using:deploy)$($deploy):8089`n" > "C:\Program Files\SplunkUniversalForwarder\etc\system\local\deploymentclient.conf"
}

function Get-Sysmon(){

    #installing sysmon
    $path = "C:\Program Files\sysmon"
    New-Item $path -ItemType Directory
    Set-Location $path
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -Outfile Sysmon.zip
    Expand-Archive Sysmon.zip -Force
    Set-Location $path\Sysmon
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/hkabubaker17/sysmon-config/main/sysmonconfig-export.xml -Outfile sysmonconfig-export.xml
    .\sysmon64.exe -accepteula -i sysmonconfig-export.xml
}


function Enable-WinRM{

$gpo = "Default Domain Policy"
$WinRM="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"
$ipv4="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"
$ipv6="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"
$srv="HKLM\SYSTEM\CurrentControlSet\Services\WinRM"
$rule="HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
$enable1="v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
$enable2="v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"


#Enable WinRM 
Set-GPRegistryValue -Name $gpo -Key $WinRM -ValueName "AllowAutoConfig" -Type DWord -Value 1
Set-GPRegistryValue -Name $gpo -Key $ipv4 -ValueName "IPv4Filter" -Type String -Value "*"
Set-GPRegistryValue -Name $gpo -Key $ipv6 -ValueName "IPv6Filter" -Type String -Value "*"

#Autostart WinRM
Set-GPRegistryValue -Name $gpo -Key $srv -ValueName "Start" -Type DWord -Value 2
Set-GPRegistryValue -Name $gpo -Key $srv -ValueName "DelayedAutostart" -Type DWord -Value 0

#Add WinRM to firewall 
Set-GPRegistryValue -Name $gpo -Key $rule -ValueName "WINRM-HTTP-In-TCP" -Type String -Value $enable1
Set-GPRegistryValue -Name $gpo -Key $rule -ValueName "WINRM-HTTP-In-TCP-PUBLIC" -Type String -Value $enable2

}


function Disable-WinRM{

$gpo = "Default Domain Policy"
$WinRM="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"
$ipv4="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"
$ipv6="HKLM\Software\Policies\Microsoft\Windows\WinRM\Service"
$srv="HKLM\SYSTEM\CurrentControlSet\Services\WinRM"
$rule="HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
$enable1="v2.31|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Domain|Profile=Private|LPort=5985|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"
$enable2="v2.31|Action=Allow|Active=FALSE|Dir=In|Protocol=6|Profile=Public|LPort=5985|RA4=LocalSubnet|RA6=LocalSubnet|App=System|Name=@FirewallAPI.dll,-30253|Desc=@FirewallAPI.dll,-30256|EmbedCtxt=@FirewallAPI.dll,-30267|"

#Enable WinRM 
Set-GPRegistryValue -Name $gpo -Key $WinRM -ValueName "AllowAutoConfig" -Type DWord -Value 1
Set-GPRegistryValue -Name $gpo -Key $ipv4 -ValueName "IPv4Filter" -Type String -Value "*"
Set-GPRegistryValue -Name $gpo -Key $ipv6 -ValueName "IPv6Filter" -Type String -Value "*"

#Autostart WinRM
Set-GPRegistryValue -Name $gpo -Key $srv -ValueName "Start" -Type DWord -Value 3
Set-GPRegistryValue -Name $gpo -Key $srv -ValueName "DelayedAutostart" -Type DWord -Value 1

#Add WinRM to firewall 
Set-GPRegistryValue -Name $gpo -Key $rule -ValueName "WINRM-HTTP-In-TCP" -Type String -Value $enable1
Set-GPRegistryValue -Name $gpo -Key $rule -ValueName "WINRM-HTTP-In-TCP-PUBLIC" -Type String -Value $enable2

}