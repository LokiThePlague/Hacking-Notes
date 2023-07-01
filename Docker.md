# Installation

```shell
# Debian
sudo apt install docker.io -y
```

# Start service

```shell
service docker start
```

#  Dockerfile

## Creation

```dockerfile
FROM ubuntu:latest

MAINTAINER Rodrigo Medina aka Loki "xxxxxx@gmail.com"

# Avoid interactive mode (prompts) while installing
ENV DEBIAN_FRONTEND noninteractive

# Install packages
RUN apt update && apt install -y net-tools \
	iputils-ping \
	curl \
	git \
	nano \
	apache2 \
	php

# Tell what do you want to share from your local machine to the container
COPY local_document.txt /var/www/html

# Apply port forwarding (in this case, 80 port of machine will be 80 port of the container)
EXPOSE 80

# Run commands when container starts (adding /bin/bash prevents certain services from disconnecting)
ENTRYPOINT service apache2 start && /bin/bash
```

## Build

```shell
# We can build dockerfile with tag (in this case v1) or without it
docker build -t my_first_image:v1 .
```

# Commands

```shell
# List docker images availables in system
docker images

# Delete image
docker rmi 123456789
docker rmi my_first_image:v1

# Delete all images in system
docker rmi $(docker images -q)

# Delete all images with 'none'
docker rmi $(docker images --filter "dangling=true" -q)

# Check all containers running in system
docker ps -a

# Run Docker container from an image
# -d or -detach: run container in background
# -i or -interactive: allow interactive input
# -t or -tty: assign virtual terminal
docker run -dit --name myContainer my_first_image:v1

# Run Docker container applying port forwarding (<port_in_host>:<port_in_container>)
docker run -dit -p 80:80 --name myContainer my_first_image:v1

# Mount for sharing a directory or file between local machine and container
docker run -dit -p 80:80 -v /home/loki/Desktop/docker/:/var/www/html/ --name myContainer my_first_image:v1

# Stop container
docker stop 123456789
docker stop myContainer

# Remove container (we can add --force for deleting it although is running)
docker rm 123456789 --force
docker rm myContainer --force

# Remove all containers in system
docker rm $(docker ps -a -q) --force

# Exec commands on a running container, we can use container id or container name (in this case the executed command is 'bash')
# -i or -interactive: allow interactive input
# -t or -tty: assign virtual terminal
docker exec -it 123456789 bash
docker exec -it myContainer bash

# List existing volumes in system
docker volume ls

# Delete all existing volumes
docker volume rm $(docker volume ls -q)

# Network
# Create available Docker networks
docker network ls

# Create new network
docker network create --subnet=<SUBNET> <NETWORK_NAME>

# Specify the network driver you want to use (bridge, overlay, mavlan, ipvlan...)
docker network create --subnet=10.10.0.0/24 --driver=bridge network1

# Assign network to existing Docker container
# As we create more networks we are assigned more network interfaces.
docker network connect <NETWORK_NAME> <CONTAINER_NAME>

# Run a Docker container by assigning it a previously created network
docker run -dit --name myContainer --network=network1 my_first_image:v1

# Delete all custom networks
docker network rm $(docker network ls -q)
```

# Docker compose

## Usage

```shell
# -d is detached
docker-compose up -d
```