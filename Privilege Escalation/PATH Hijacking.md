**PATH Hijacking** is a technique used by attackers to *hijack commands* from a Unix/Linux system by manipulating the *PATH*. The PATH is an environment variable that defines the search paths for executable files on the system.

In some compiled binaries, some of the internally defined commands may be indicated with a relative path instead of an absolute path. This means that the binary searches for executable files in the paths specified in the PATH, instead of using the absolute path of the executable file.

If an attacker is able to alter the PATH and create a new file with the same name as one of the commands defined internally in the binary, they can get the binary to execute the malicious version of the command instead of the legitimate version.

For example, if a compiled binary uses the "*ls*" command without its absolute path in its code and the attacker creates a malicious file named "ls" in one of the paths specified in the PATH, the binary will execute the malicious file instead of the legitimate "*ls*" command when called.

To prevent PATH Hijacking, it is *recommended* to use *absolute paths* instead of relative paths in the internally defined commands in the compiled binaries. In addition, it is important to ensure that the paths in the PATH are controlled and limited to the paths necessary for the system. It is also recommended to use the option of execution permissions for executable files only for authorized users and groups.

# Example

Let's suppose that we have a script created by *root* with *execution* permissions for all users or with [[SUID]] permission inside which is being called by a *relative path* to the *whoami* command.

We could *add* to the *PATH* the *tmp* directory so that when *whoami* is called as a relative path, it looks *first* in *tmp* before the rest of the *PATH*:

```bash
export PATH=/tmp/:$PATH
```

In this case we could go to the *tmp* directory, create a *script* called *whoami*, give it *execution* permissions and include the following:

```bash
bash -p
```

Doing this will give us a *privileged bash*.