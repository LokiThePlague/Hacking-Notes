When we talk about '**Python Library Hijacking**', what we are referring to is an attack technique that takes advantage of the way Python searches for and loads libraries to inject malicious code into a script. The attack occurs when an attacker creates or modifies a library in a path accessible by the Python script, so that when the script imports it, the malicious version is loaded instead of the legitimate one.

The way the attack is carried out is as follows: the attacker looks for a library used by the script and replaces it with his own malicious version. This library can be a standard Python library or an external library downloaded and installed by the user. The attacker places his malicious version of the library in an accessible path before the legitimate library is found.

In general, Python starts by looking for these libraries in the current working directory and then in the paths defined in the sys.path variable. If the attacker has write access to any of the paths defined in sys.path, he can place his own malicious version of the library there and cause the script to load it instead of the legitimate one.

In addition, the attacker can also create his own library in the current working directory, since Python starts searching in this directory by default. If during the loading of these libraries from the legitimate script, the attacker manages to hijack them, then he will get an alternative execution of the program.

# Example

In this example we are going to perform a *user pivoting*.

Suppose we do a *sudo -l* and in the [[Sudoers]] file there is a query that allows us to run a *Python* script called *example.py* in the */tmp* directory under the name of the *victim* user:

```bash
loki ALL=(victim) NOPASSWD: /usr/bin/python3 /tmp/example.py
```

The *example.py* file is *readable* but *not writable*:

```bash
-rw-rw-r-- victim victim 129 Mar 6 16:45 example.py
```

We can run this file as the user *victim* without being prompted for a password:

```bash
sudo -u victim python3 /tmp/example.py
```

Suppose the *example.py* script uses the *Python* *requests* library. With the following command we can see the *path* where *Python* libraries are stored:

```bash
python3 -c 'import sys; print(sys.path)'
```

If we look at the response we see that at the *beginning* of the *path* there is an *empty string (' ')*, this refers to the *current working directory*, which will be *prioritized* when looking for the library.

----
> In the *path*, resources are always sought from *left to right*.
----

We can create a script called *requests.py* which will prioritize *example.py* on import in the following cases:
- If we create *requests.py* in the *same working directory* of *example.py*
- If we create *requests.py* in a path *before* the original *requests* library. For example, if the path of the original library is */usr/lib/python*, we should create it in */usr* or */lib*.
- If we have *write* permissions on the original *requests* library and we inject our code.

In our *sys.py* script we can introduce the following:

```python
import os

os.system("bash -p")
```

In this case when we run the *example.py* script as the *victim* user, and the script imports the *requests* library, it will actually be using our own script and will give us a *bash* with its user.