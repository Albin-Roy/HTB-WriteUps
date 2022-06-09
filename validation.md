# Validation - HackTheBox

![](/root/.config/marktext/images/2022-06-08-13-34-21-image.png)





## 1. Enumeration

### Nmap Initial Scan

```
┌──(root💀kali)-[~/htb/validation]
└─# cat nmap_init  
# Nmap 7.92 scan initiated Wed Jun  8 13:36:56 2022 as: nmap -sC -sV -oN nmap_init 10.129.95.235
Nmap scan report for 10.129.95.235
Host is up (0.15s latency).
Not shown: 992 closed tcp ports (reset)
PORT     STATE    SERVICE       VERSION
22/tcp   open     ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open     http          Apache httpd 2.4.48 ((Debian))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.48 (Debian)
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
8080/tcp open     http          nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun  8 13:37:14 2022 -- 1 IP address (1 host up) scanned in 17.98 seconds
                                                                                               
```



### Union SQL Injection

![](/root/.config/marktext/images/2022-06-08-14-31-28-image.png)



![](/root/.config/marktext/images/2022-06-08-14-31-36-image.png)





Now, writes shell code into shell.php

![](/root/.config/marktext/images/2022-06-08-14-39-45-image.png)



While passing system command to the url we can execute system commands.

![](/root/.config/marktext/images/2022-06-08-14-49-21-image.png)





Let's create a bash reverse shell by turning listener on netcat

![](/root/.config/marktext/images/2022-06-08-14-50-59-image.png)





We now logged in as www-data,

```
┌──(root💀kali)-[~/htb/validation]
└─# nc -lvnp 1234                            
listening on [any] 1234 ...
connect to [10.10.16.18] from (UNKNOWN) [10.129.95.235] 39514
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ whoami
whoami
www-data

```





Now we got some credentials,

```
www-data@validation:/var/www/html$ cat config.php
cat config.php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>

```





As there is no python installed, we can make interactive shell using,

```
www-data@validation:/var/www/html$ script -q /dev/null bash
```





The password we previously got looks like a global one, lets try - 

```
root@validation:/var/www/html# cd /home
root@validation:/home# ls
htb
root@validation:/home# cd htb
root@validation:/home/htb# ls
user.txt
root@validation:/home/htb# cat user.txt 
c55c4f48f5dc7a57469823b7cd13f39d
root@validation:/home/htb# cat /root/root.txt 
9994b530a9f83091fe4bafe64981ee27

```


