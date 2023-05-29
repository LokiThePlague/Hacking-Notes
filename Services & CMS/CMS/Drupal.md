----
> We can test Drupal vulns with this playground: [vulhub](https://github.com/vulhub/vulhub/tree/master/drupal/CVE-2018-7600).
----

# Enumeration

## whatweb

We can scan with *whatweb* for checking, for example, Drupal version:

```shell
# CAUTION: If we test in our local machine we need to provide '127.0.0.1' instead of 'localhost'
whatweb http://{URL}:{PORT}/
```

## Droopescan

> Note: This project is no longer maintained or developed, but it is still useful.

Droopescan is plugin-based scanner that aids security researchers in identifying issues with several CMS.

### Installation

We can clone droopescan from it's [official repository](https://github.com/SamJoan/droopescan), and then, we can install it:

```shell
sudo python3 setup.py install
sudo pip3 install -r requirements.txt
```

### Usage

```shell
droopescan scan drupal --url http://{URL}:{PORT}/
```