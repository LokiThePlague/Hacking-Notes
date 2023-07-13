The *kernel* is the central part of the Linux operating system, which is responsible for managing system resources such as memory, processes, files and devices. Due to its critical role in the system, any vulnerability in the kernel can have serious consequences for system security.

In older versions of the Linux kernel, vulnerabilities have been discovered that can be exploited to allow attackers to gain *root* access to the system.

Elevation of privilege refers to the technique used by attackers to gain elevated permissions on the system, such as *root*, when they only have limited permissions. For example, a user with limited permissions on the system could use a vulnerability in the kernel to gain root access and subsequently compromise the system.

Kernel vulnerabilities can be exploited in several ways. For example, an attacker could exploit a vulnerability in a device driver to gain access to the kernel and perform malicious operations. Another common way kernel vulnerabilities are exploited is through the use of buffer overflow techniques, which allow attackers to write malicious code in memory areas reserved for the kernel.

To mitigate the risk of kernel vulnerabilities, it is important to keep the operating system up to date and apply security patches as soon as they become available.

# Enumeration

## Manual

To manually check if the *kernel* can be *exploited* to elevate privileges, we must make sure that the *kernel* is as *old as possible* (for example in *Linux*, very old kernel versions are *2.x* or *3.x*) and we can search for it with the **searchsploit** tool:

```bash
searchsploit kernel privilege escalation
```

## Automated

If we find it difficult to find a specific exploit we have tools like [linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester) that *automatically* tells us which *kernel-level exploits* we can launch to elevate our privilege. It works in a similar way to [lse](https://github.com/diego-treitos/linux-smart-enumeration) but focused on exploiting the *kernel* specifically.

# Example

For this example let's assume that we are inside a machine with an *unprivileged* user and this machine has an *Ubuntu* with a *kernel* version *3.6*. If we search for an exploit for this version with **searchsploit** we get this one:

```bash
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)
```

This *c-compiled* script exploits a [[Race Condition]] to introduce a new line at the top of */etc/passwd* with the *password* of your choice with *administrator* permissions. It also creates a backup of the original */etc/passwd*.

We bring the exploit to the current working directory and rename it for ease of use:

```bash
searchsploit -m linux/local/40839.c

mv 40839.c dirtycow.c
```

We must see if we can *compile* it on the victim machine, because in case we can't, we must compile it on our machine and then transfer it to the victim machine.

The script code itself tells you how to compile it:

```bash
gcc -pthread dirty.c -o dirty -lcrypt
```

And then we can run the compiled script on the victim machine (in this case we have called it *dirty* in the previous step) with *./dirty*.