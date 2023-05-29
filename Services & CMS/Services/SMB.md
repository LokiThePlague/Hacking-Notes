# smbclient

## Usage

```shell
# List existing resources shared by smb with null session (-N)
smbclient -L {IP} -N

# Connect to smb directory with null session (-N) and with valid username (-U)
smbclient //{IP}/myshare -N
smbclient //{IP}/myshare -U {USERNAME}
```

## Commands

```shell
# Upload file
put file.txt

# Download file
get file.txt
```

# smbmap

## Usage

```shell
# List existing resources shared by smb showing directory permissions
smbmap -H {IP}

# Username or 'guest' for guest access.
-u {USERNAME}

# Password or "" for guest access.
-p {PASSWORD}

# Directory path or '.' for current path.
-d {DIRECTORY}

# Target IP.
-H {IP}

# Run command.
-x '{COMMAND}'

# List drives.
-L

# Show content of selected drive, in this case, C drive.
-r 'C$'

# Upload a local file into selected path and selected drive.
--upload '{PATH_TO_FILE_TO_UPLOAD}' 'C$\{DESTINATION_PATH}'

# Download specified file from selected drive.
--download 'C$\{FILE_PATH}'
```

# Nmap

## Scripts

```shell
—script smb-os-discovery

—script smb-protocols

—script smb-security-mode

—script smb-enum-sessions

# We can add ",smb-ls" for listing
—script smb-enum-shares

—script smb-enum-users

—script smb-server-stats

—script smb-enum-domains

—script smb-enum-groups

—script smb-enum-services

# Sessions, shares, users, stats, domains, groups and services require authentication
--script-args smbusername={USERNAME}, smbpassword={PASSWORD}
```

# cifs

With cifs, we can mount a smb directory into our local machine, very useful for working with smb directories.

## Installation

```shell
# Debian
sudo apt install cifs-utils
```

## Usage

```shell
# Mount in previous created folder (in this case /mnt/mounted) with null access
mount -t cifs //{IP}/{SMB_DIRECTORY} /mnt/mounted -o username=null,password=null,domain=,rw

# Umount
umount /mnt/mounted
```