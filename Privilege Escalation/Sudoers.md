The */etc/sudoers* file is a configuration file on Linux systems that is used to control user access to the different actions they can perform on the system. This file contains a list of users and user groups that have permissions to perform administrative tasks on the system.

The "*sudo*" command allows users to execute commands as a superuser or as another user with special privileges. The sudoers file specifies which users can execute which commands with sudo and with which privileges.

Abusing privileges at the sudoers level is a technique used by attackers to elevate their level of access on a compromised system. If an attacker is able to gain access to an account with sudo permissions in the sudoers file, they can execute commands with special privileges and perform malicious actions on the system.

The "*sudo -l*" command is used to list the sudo permissions of a particular user. When this command is executed, it displays a list of the commands that the user has permission to execute and under what conditions.

To prevent privilege abuse at the sudoers level, it is recommended to maintain proper permissions in the sudoers file and limit the number of users with sudo permissions. In addition, it is important to regularly monitor the sudoers file and look for unexpected or suspicious changes to its contents.

# Example

Let's suppose we create a new user *loki*, open */etc/sudoers* and introduce the following *policy*:

```bash
loki ALL=(root) NOPASSWD: /usr/bin/awk -> politica en el /etc/sudoers
```

The user *loki* will be able to execute *as root*, *without password*, the *awk* command.

If now as the user *loki* we do a *sudo -l*, it will tell us that we can execute the following operation as *root*:

```bash
(root) NOPASSWD: /usr/bin/awk
```

We can also notice that if we do a *sudo awk* it does not ask for a password, while with the rest of the binaries it does.

If we search the [GTFObins](https://gtfobins.github.io/) web site for "*awk*" we see that we have a potential way to *spawn a shell* with the following command:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
```

This is just one example, but we have many more with many different binaries on the [GTFObins](https://gtfobins.github.io/) web site.