Zone transfer attacks, also known as *AXFR* attacks, are a type of attack that targets *DNS* (*Domain Name System*) servers and allows attackers to obtain sensitive information about an organization's domains.

In simple terms, DNS servers are responsible for translating human-readable domain names into machine-usable IP addresses. AXFR attacks allow attackers to obtain information about DNS records stored on a DNS server.

The AXFR attack is carried out by sending a zone transfer request from a spoofed DNS server to a legitimate DNS server. This request is made using the DNS zone transfer protocol (AXFR), which is used by DNS servers to transfer DNS records from one server to another.

If the legitimate DNS server is not configured correctly, it may respond to the zone transfer request and provide the attacker with detailed information about the DNS records stored on the server. This includes information such as domain names, IP addresses, email servers and other sensitive information that can be used in future attacks.

The dig command is a command line tool used to perform DNS queries and obtain information about DNS records for a specific domain.

The syntax for applying AXFR on a DNS server is as follows:

```bash
dig @<DNS-server> <domain-name> AXFR
```

Where:
- \<**DNS-server**> is the IP address of the DNS server to be queried.
- \<**domain-name**> is the domain name for which you want to obtain the zone transfer.
- **AXFR** is the type of query to be performed, which indicates to the DNS server that a full zone transfer is desired.

To prevent AXFR attacks, it is important for network administrators to properly configure DNS servers and limit zone transfer access to authorized servers only. It is also important to keep DNS server software up to date and use strong encryption and authentication techniques to protect data being transmitted over the network. Administrators can also use DNS monitoring tools to detect and prevent potential zone transfer attacks.

# Example

For the realization of this example we will download the following resource:

```bash
svn checkout https://github.com/vulhub/vulhub/trunk/dns/dns-zone-transfer
```

We can install it with the *docker-compose up -d* command.

If we open the *vulhub.db* file inside the */etc/bind* directory of the deployed container, we can see the *subdomains* and the *IP* they resolve to. If we manage to do an *AXFR* we will be able to obtain all this data.

We are going to use the **dig** tool to make the requests:

```bash
# List nameservers with the respective IPs
dig ns @127.0.0.1 vulhub.org

# Enumerar servidores de correo
dig mx @127.0.0.1 vulhub.org

# See all the information about the area
dig axfr @127.0.0.1 vulhub.org
```

With *AXFR* you save yourself as an attacker from brute force and we can go straight to what we are interested in because we know which *subdomains* exist and which do not.