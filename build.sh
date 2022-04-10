#!/bin/bash

docker build -t dcastro/linux-run:latest . -f docker/Dockerfile.run
docker build -t dcastro/linux-deb:latest . -f docker/Dockerfile.deb

docker run -it --rm dcastro/linux-build:latest
