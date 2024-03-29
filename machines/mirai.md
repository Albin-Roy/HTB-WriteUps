# Mirai - HackTheBox WriteUp

![](/root/.config/marktext/images/2022-08-01-00-14-22-image.png)  

## 1. Enumeration

### Nmap Initial Scan

```
┌──(root💀kali)-[~/htb/machines/mirai]
└─# nmap -sC -sV -oN nmap_init 10.10.10.48                
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-31 11:13 EDT
Nmap scan report for 10.10.10.48
Host is up (0.22s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
53/tcp open  domain  dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp open  http    lighttpd 1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: lighttpd/1.4.35
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
```

### Web Enumeration

Open browser and browse for http://10.10.10.48. Observe that the page is not found. Intercept  the request in burp and change the value of host.

![](/root/.config/marktext/images/2022-08-01-00-24-26-image.png)  



Set host to fake, send the  request and analyze the response.  

![](/root/.config/marktext/images/2022-08-01-00-38-11-image.png)

When host is changed to one that does not exist, the web app responses with a warning message which reveals one of the application used by the target.

![](/root/.config/marktext/images/2022-08-01-06-00-10-image.png)

This reveals that the web application is using pi-hole v3.1.4 whcih has several vulnerabilities.  

Adding pi.hole with the target ip to hosts file give access to the application. 
