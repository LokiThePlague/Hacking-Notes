```shell
# Identify web technologies
whatweb {IP}

# Tools for applying fuzzing
wfuzz
fuff
gobuster
dirb
dirsearch

# Make http request
http {IP}

# Retrieve web page
# We can add "| more" because it returns a lot of information and more split it by pages
curl {IP}

# Upload file to web server
curl {IP} --upload-file {FILE}

# Move file / rename file inside web server
curl -X MOVE --header "Destination:http://{IP}{NEW_FILE}" http://{IP}/{OLD_FILE}

# Retrieve web files
wget "http://{IP}/{PAGE_TO_DOWNLOAD}"

# Parse HTML into a more readable file
lynx http://{IP}
```

# Tools

## Nmap

```shell
# Get common directories found in web and marks interesting folders
--script http-enum -p{PORT}

# Get web headers and find information like XSS enabled or not, IIS version ...
--script http-headers -p{PORT}

# Get supported http methodsand marks potentially dangerous ones
--script http-methods --script-args http-methods.url-path=/{WEB_DIRECTORY}/ -p{PORT}

# Get information about webdav installations
--script http-webdav-scan --script-args http-methods.url-path=/{WEB_DIRECTORY}/ -p{PORT}

# Get banner information
--script banner -p{PORT}
```