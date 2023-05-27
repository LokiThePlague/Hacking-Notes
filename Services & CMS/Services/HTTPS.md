----
> For HTTPS, we can use the same enumeration techniques as in [[HTTP]]. Additionally we can use the techniques showed below.
----

We can view the SSL certificate searching for subdomains and other important stuff. We can check it with openssl:

```shell
openssl s_client -connect {URL}:443
```

For checking vulnerabilities in SSL, we can use sslscan:

```shell
sslscan {URL}
```