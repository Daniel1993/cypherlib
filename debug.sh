#!/bin/bash

docker build -t dcastro/linux-deb:latest . -f docker/Dockerfile.deb
docker run -it --rm dcastro/linux-deb:latest
