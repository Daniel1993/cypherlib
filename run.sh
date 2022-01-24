#!/bin/bash

docker build -t dcastro/linux-run:latest . -f docker/Dockerfile.run
docker run -it --rm dcastro/linux-run:latest
