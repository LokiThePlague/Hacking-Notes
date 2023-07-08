The **Open Redirect** vulnerability, is a common vulnerability in web applications that can be exploited by attackers to direct users to malicious websites. This vulnerability occurs when a web application allows attackers to manipulate the URL of a redirect page to redirect the user to a malicious website.

For example, suppose a web application uses a redirect parameter in a URL to direct the user to an external page after they have authenticated. If this URL does not properly validate the redirect parameter and allows attackers to modify it, the attackers can direct the user to a malicious website, instead of the legitimate website.

An example of how attackers can exploit the open redirect vulnerability is by creating phishing emails that look legitimate, but actually contain manipulated links that redirect users to a malicious website. Attackers may use social engineering techniques to convince the user to click on the link, such as offering an attractive offer or a unique opportunity.

To prevent the open redirect vulnerability, it is important for developers to implement appropriate security measures in their code, such as validating redirect URLs and limiting redirect options to legitimate websites. Developers can also use secure encoding techniques to prevent URL manipulation, such as special character encoding and stripping invalid characters.

# Example

## Example 1

For the realization of this example we are going to download the following lab:

```bash
svn checkout https://github.com/blabla1337/skf-labs/trunk/nodeJs/Url-redirection
```

And then we are going to run the service:

```bash
npm install
npm start
```

Once executed, we can go to *localhost* on port *5000*.

When we enter the page it indicates that we are in the old page, and if we click on the link it redirects us to the new one, which is *\http://localhost:5000/newsite*. Let's analyze this redirection with **BurpSuite**.

The following request is being processed:

```bash
POST /redirect?newurl=/newsite HTTP/1.1
```

In this case, as we can put in the *newurl* parameter, for example, *\https://google.es* and this redirects us to *Google*, an *Open Redirect* would be applied:

```
POST /redirect?newurl=https://google.es HTTP/1.1
```


## Example 2

For the realization of this example we are going to download the following lab:

```bash
svn checkout https://github.com/blabla1337/skf-labs/trunk/nodeJs/Url-redirection-harder
```

And then we are going to run the service:

```bash
npm install
npm start
```

Once executed, we can go to *localhost* on port *5000*.

When we enter the page it indicates that we are in the old page, and if we click on the link it redirects us to the new one, which is *\http://localhost:5000/newsite*. Let's analyze this redirection with **BurpSuite**.

The following request is being processed:

```bash
POST /redirect?newurl=/newsite HTTP/1.1
```

If we try to do the same as in the previous example and try to redirect to *Google*, it will tell us that it is not possible to put *dots* in the redirect.

To fix this we must *url-encode* the dot in the redirect and *re-url-encode* it:

```bash
# Original request
POST /redirect?newurl=https://google.es HTTP/1.1

# Dot url-encoded request
POST /redirect?newurl=https://google%2ees HTTP/1.1

# Dot-double url-encoded request
POST /redirect?newurl=https://google%252ees HTTP/1.1
```

## Example 3

For the realization of this example we are going to download the following lab:

```bash
svn checkout https://github.com/blabla1337/skf-labs/trunk/nodeJs/Url-redirection-harder2
```

And then we are going to run the service:

```bash
npm install
npm start
```

Once executed, we can go to *localhost* on port *5000*.

When we enter the page it indicates that we are in the old page, and if we click on the link it redirects us to the new one, which is *\http://localhost:5000/newsite*. Let's analyze this redirection with **BurpSuite**.

The following request is being processed:

```bash
POST /redirect?newurl=/newsite HTTP/1.1
```

If we try to do the same as in the previous example and try to redirect to *Google*, it will tell us that it is not possible to put *dots* nor *slashes* in the redirect.

To fix this we must *url-encode* the *dot* in the redirect and *re-url-encode* it:

```bash
# Original request
POST /redirect?newurl=https://google.es HTTP/1.1

# Dot url-encoded request
POST /redirect?newurl=https://google%2ees HTTP/1.1

# Dot-double url-encoded request
POST /redirect?newurl=https://google%252ees HTTP/1.1
```

Right now the slashes give us conflict, but we can take advantage of the fact that in the HTTPS protocol it is not necessary to include them to bypass it:

```bash
POST /redirect?newurl=https:google%252ees HTTP/1.1
```

----
> *Open Redirect* as such is very simple, but its power lies in its combination with other vulnerabilities.
----