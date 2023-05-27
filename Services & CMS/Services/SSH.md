# Usage

```shell
ssh {USERNAME}@{IP} -p {PORT}
```

# Tools

## Netcat

We can grab banner with netcat.

```shell
nc {IP} {PORT}
```

## Nmap

```shell
# Enum all algorithms supported by server
--script ssh2-enum-algos -p {PORT}

# Get SSH hostkeys
--script ssh-hostkey --script-args ssh_hostkey=full -p {PORT}

# Get authorization methods for given username
--script ssh-auth-methods --script-args="ssh.user={USERNAME}" -p {PORT}

# Brute force
--script ssh-brute --script-args userdb={PATH_TO_LIST} -p {PORT}
```

## [[Hydra]]

### Wordlists

```shell
# Users
/usr/share/metasploit-framework/data/wordlists/common_users.txt

# Passwords
/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

# rockyou
/usr/share/wordlists/rockyou.txt
```