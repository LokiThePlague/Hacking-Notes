----
> We can test Magento vulns with this playground: [vulhub](https://github.com/vulhub/vulhub/tree/master/magento/2.2-sqli).
----

# Enumeration

## Magescan

With magescan we can check existing paths, Magento version and other important stuff.

### Installation

In order to install magescan, we need to clone it's [repository](https://github.com/steverobbins/magescan) and download the latest [magescan.phar](https://github.com/steverobbins/magescan/releases) file.

### Usage

```shell
php magescan.phar scan:all http://{URL}:{PORT}
```