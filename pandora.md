# 

# Pandora - HackTheBox WriteUp



## 1. Nmap Scan

```
# Nmap 7.92 scan initiated Tue May 31 08:00:26 2022 as: nmap -sC -sV -oN nmap_scan 10.129.99.118
Nmap scan report for 10.129.99.118
Host is up (0.69s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue May 31 08:01:03 2022 -- 1 IP address (1 host up) scanned in 36.96 seconds
```



check port 80 on browser

![](/assets/images/2022-06-01-00-30-19-image.png)



### Nmap UDP Scan

```
# Nmap 7.92 scan initiated Tue May 31 12:44:11 2022 as: nmap -sU -oN nmap_U 10.129.99.118
Nmap scan report for panda.htb (10.129.99.118)
Host is up (0.26s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
161/udp   open          snmp
502/udp   open|filtered mbap
20679/udp open|filtered unknown

# Nmap done at Tue May 31 13:02:13 2022 -- 1 IP address (1 host up) scanned in 1081.39 seconds

```



## 2. SNMP Enumeration

```
snmpbulkwalk -Cr1000 -c public -v2c 10.129.99.118 > snmp1
```

from the results we get "daniel" as username and password "HotelBabylon23"

```
HOST-RESOURCES-MIB::hrSWRunParameters.975 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
HOST-RESOURCES-MIB::hrSWRunParameters.985 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
HOST-RESOURCES-MIB::hrSWRunParameters.987 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.991 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.1041 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.1042 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1045 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.1136 = STRING: "-u daniel -p HotelBabylon23"
```



## 2. SSH into machine as daniel

```
ssh daniel@10.129.99.118
```

Enter the password



No user.txt

cd /etc/apache2

we get these files and directories,

```
apache2.conf  conf-available  conf-enabled  envvars  magic  mods-available  mods-enabled  ports.conf  sites-available  sites-enabled

```

cd sites-available

we get these files,

```
000-default.conf  pandora.conf
```

```
cat pandora.conf


<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

So there is subdomain running on localhost port 80.

add pandora.panda.htb to /etc/hosts



## 3. Port Forwarding

```
ssh -L 8000:127.0.0.1:80 daniel@10.129.99.118
```



Now, browse for localhost:8000 on our browser.

![](/assets/images/2022-06-01-00-31-29-image.png)


