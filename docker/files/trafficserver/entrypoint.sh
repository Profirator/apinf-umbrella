#!/bin/sh

mkdir /templates/config

mustache /config/config.yml /templates/logging.yaml.mustache > /templates/logging.yaml
mustache /config/config.yml /templates/plugin.config.mustache > /templates/plugin.config
mustache /config/config.yml /templates/records.config.mustache > /templates/records.config
mustache /config/config.yml /templates/remap.config.mustache > /templates/remap.config
mustache /config/config.yml /templates/storage.config.mustache > /templates/storage.config
mustache /config/config.yml /templates/records.config.mustache
cp -a /templates/. /opt/ts/etc/trafficserver/

/opt/ts/bin/traffic_manager