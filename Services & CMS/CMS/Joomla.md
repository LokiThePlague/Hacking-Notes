----
> We can test Joomla vulns with this playground: [vulhub](https://github.com/vulhub/vulhub/tree/master/joomla/CVE-2015-8562).
----

# Enumeration

## JoomScan

With JoomScan we can scan a Joomla CMS and find vulnerabilities and other stuff.

### Installation

Follow the instruction in the [official repository](https://github.com/OWASP/joomscan) for the installation.

### Usage

```shell
perl joomscan.pl -u http://{URL}:{PORT}/
```

Additionally, we can view the report generated by previous command in html:

```shell
cd reports/{REPORT_FOLDER}
mv {HTML_REPORT} index.html
sudo python3 -m http.server 80
```

Now we can go to *localhost* and view the results in html format.