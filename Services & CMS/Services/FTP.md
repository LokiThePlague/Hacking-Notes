# Usage

```shell
ftp {IP}
```

Inside ftp command, we can login with 'anonymous' user and empty password for anonymous login.

# Tools

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

## Nmap

### Scripts

```shell
# Anonymous login
--script ftp-anon -p {PORT}

# Brute-force
--script ftp-brute --script-args userdb={PATH_TO_LIST} -p {PORT}
```