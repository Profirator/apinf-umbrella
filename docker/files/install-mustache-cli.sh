#!/bin/sh

mkdir /opt/mustache
cd /opt/mustache

# install mustache cli for creating the config
wget https://github.com/cbroglie/mustache/releases/download/v1.3.0/mustache_1.3.0_linux_amd64.tar.gz
tar xf mustache_1.3.0_linux_amd64.tar.gz -C /opt/mustache