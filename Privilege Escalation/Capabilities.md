On Linux systems, **capabilities** are a security feature that allows users to perform actions that normally require *root* privileges, without having to be granted full root access. This is done to improve security, since a process that only needs certain privileges can obtain them without having to run as root.

Capabilities are divided into *3 types*:
- **Effective capabilities**: these are the permissions that apply directly to the process that owns them. These permissions determine the actions that the process can perform. For example, the capability "*CAP_NET_ADMIN*" allows the process to modify the network configuration.
- **Inheritable capabilities**: these are the permissions that are inherited by the child processes that are created. These permissions can be additional to the effective permissions that the parent process already has. For example, if a parent process has the capability "*CAP_NET_ADMIN*" and this capability is configured as inheritable, then the child processes will also have the capability "*CAP_NET_ADMIN*".
- **Permitted capabilities**: these are the permissions that a process is allowed to have. This includes both effective and inherited permissions. A process can only execute actions for which it has permitted permissions. For example, if a process has the capability "*CAP_NET_ADMIN*" and the capability "*CAP_SETUID*" configured as permitted, then the process can modify the network configuration and change its *UID* (*User ID*).

However, some capabilities can pose a security risk if assigned to certain binaries. For example, the capability *cap_setuid* allows a process to set the UID (User ID) of a process to a value other than its own, which may allow a malicious user to execute malicious code with elevated privileges.

To *list* the capabilities of a binary file on Linux, you can use the *getcap* command. This command displays the effective, inheritable and allowed capabilities of the file. For example, to view the capabilities of the binary file */usr/bin/ping*, you can run the following command in the terminal:

```bash
getcap /usr/bin/ping
```

The output of the command will show the capabilities assigned to the file:

```bash
/usr/bin/ping = cap_net_admin,cap_net_raw+ep
```

In this case, the ping binary has two capabilities assigned: *cap_net_admin* and *cap_net_raw+ep*. The last capability (*cap_net_raw+ep*) indicates that the file has the execution bit (*ep*) high and the *cap_net_raw* capability assigned.

To *assign* a capability to a binary file, you can use the *setcap* command. This command sets the effective, inheritable and allowed capabilities for the specified file.

For example, to assign the capability *cap_net_admin* to the binary file */usr/bin/my_program*, you can run the following command in the terminal:

```bash
sudo setcap cap_net_admin+ep /usr/bin/my_program
```

In this case, the command gives the capability *cap_net_admin* to the file */usr/bin/my_program*, and also sets the execution bit high (*ep*). Now, the my_program file will have permissions to manage the network configuration.

The elevated execution bit (ep) is a special attribute that can be set in a binary file in Linux. This attribute is used in conjunction with capabilities to allow a file to run with special permissions, even if the user running the file does not have superuser privileges.

When a binary file has the elevated execution bit set, it can be executed with the effective capabilities assigned to the file, rather than the capabilities of the user executing it. This means that the file can perform actions that are normally only allowed to users with elevated privileges.

It is important to note that the allowed permissions can be further limited by using a Mandatory Access Control (MAC) mechanism, such as *SELinux* or *AppArmor*, which restrict the actions that processes can perform based on the security policy of the system.

# Enumeration

We can *list* all the files that have *capabilities* with the following command:

```bash
getcap -r / 2>/dev/null
```

# Example

An example of a capability that has a risk is *cap_setuid+ep*, which allows you to control your *user id*. Assume that the *python3* binary has this capability. We could obtain a *privileged bash* in this way:

```bash
python3 -c 'import os; os.setuid(0); os.system("bash")'
```

We should not be able to set our user id to 0 (*root*), but since the binary has that capability, we can and we get a *privileged bash*.

----
> Other dangerous capabilities can be viewed on the [GTFObins](https://gtfobins.github.io/) website.
----