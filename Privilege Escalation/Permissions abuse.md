On Linux systems, files and directories have permissions that are used to control access to them. Permissions are divided into three categories: owner, group and other. Each category can have read, write and execute permissions. The permissions of a file can be changed by the owner or by the superuser of the system.

Improperly implemented permissions abuse occurs when the permissions of a critical file are set incorrectly, allowing an unauthorized user to access or modify the file. This can allow an attacker to read confidential information, modify important files, execute malicious commands or even gain superuser access to the system.

Thus, an experienced attacker could take advantage of this flaw to elevate his privileges in the best case scenario. One of the tools in charge of applying this recognition on the system is '[lse](https://github.com/diego-treitos/linux-smart-enumeration)'. Linux Smart Enumeration (LSE) is a security enumeration tool for Linux-based operating systems, designed to help system administrators and security auditors identify and assess vulnerabilities and weaknesses in system configuration.

[lse](https://github.com/diego-treitos/linux-smart-enumeration) is designed to be easy to use and provides clear and readable output to facilitate the identification of security issues. The tool uses standard Linux commands and runs at the command line, which means that no additional software is required. In addition, it lists a wide range of system information, including users, groups, services, open ports, scheduled tasks, file permissions, environment variables and firewall settings, among others.

# Enumeration

## Manual

We can search for *permissions* manually as follows:

```bash
find / -writable 2>/dev/null

# We hide an unwanted output
find / -writable 2>/dev/null -v "proc"

# We hide several outputs not desired
find / -writable 2>/dev/null -vE "python3.10|proc"
```

## Automated

### lse

With the [lse](https://github.com/diego-treitos/linux-smart-enumeration) tool we can search for security flaws in **Linux** systems in an automated way.

# Example

Let's suppose that after the enumeration we have detected that in the file */etc/passwd* we have *write* permissions.

Although by default we cannot obtain the hashes of the passwords of the user, since these are stored in the */etc/shadow*, something that we could do is to *generate* a new *password* encrypted with the **openssl** tool and to replace the *x* of the user that we want in the */etc/passwd*:

```bash
openssl passwd
```

If for example we have generated a password "*hello*" and encrypted it and entered it in */etc/passwd*, we can now authenticate as the required user with the password "*hello*", since it skips */etc/shadow*.