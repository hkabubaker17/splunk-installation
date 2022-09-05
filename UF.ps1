Set-Location "C:\Users\Public\Downloads"
Invoke-WebRequest -Uri https://raw.githubusercontent.com/hkabubaker17/splunk-installation/main/lib.ps1 -Outfile lib.ps1

Import-Module .\lib.ps1
$deploy = Read-Host -Prompt "Enter the deployment server ip"

#Enable-WinRM
#Disable-WinRM


Get-Splunk
Get-Sysmon

#Install splunk and sysmon to all domain computers
$computers = Get-ADComputer -Filter * -Properties * | Select -Property Name -Skip 1


foreach ($computer in $computers){
    Invoke-Command -ComputerName $computer.Name -ScriptBlock ${Function:Get-Splunk}
}

foreach ($computer in $computers){
    Invoke-Command -ComputerName $computer.Name -ScriptBlock ${Function:Get-Sysmon}
}

foreach ($computer in $computers){
    Invoke-Command -ComputerName $computer.Name -ScriptBlock {
        Remove-Item "C:\Users\Public\Downloads\splunkforwarder.msi" -Force
        Remove-Item "C:\Program Files\sysmon" -Force
    }
}

foreach ($computer in $computers){
    Invoke-Command -ComputerName $computer.Name -ScriptBlock ${Function:Config-Splunk}
}

Config-Splunk