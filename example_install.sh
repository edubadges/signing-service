#!/bin/bash

#############################################################################
# COLOURS AND MARKUP
#############################################################################
red='\033[0;31m'            # Red
green='\033[0;49;92m'       # Green
yellow='\033[0;49;93m'      # Yellow
white='\033[1;37m'          # White
grey='\033[1;49;30m'        # Grey
nc='\033[0m'                # No color
clear

echo -e "${yellow}
# Cloning signing-service code (branch master)
############################################################################${nc}"
cd /var/docker/tsob/
git clone --single-branch -b master https://github.com/edubadges/signing-service
cd /var/docker/tsob/signing-service
echo -e "${green}Done....${nc}"

echo -e "${yellow}
# Copy local settings file (settings_local.py)
#############################################################################${nc}"
cp /var/docker/tsob/config/tsob/settings_local.py /var/docker/tsob/signing-service/tsob/settings/settings_local.py
cp /var/docker/tsob/config/tsob/development.py /var/docker/tsob/signing-service/tsob/settings/development.py
cp /var/docker/tsob/config/tsob/production.py /var/docker/tsob/signing-service/tsob/settings/production.py
echo -e "${green}Done....${nc}"

echo -e "${yellow}
# Build the docker image AKA run first_build.sh
#############################################################################${nc}"
cd /var/docker/tsob
docker-compose build
echo -e "${green}Done....${nc}"

echo -e "${yellow}
# Bring the docker container down then up, remove exited containers
#############################################################################${nc}"
docker-compose down
docker-compose up -d
docker ps -a
echo -e "${green}Ready!${nc}"
