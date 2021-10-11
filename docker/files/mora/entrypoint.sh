#!/bin/sh

mustache /config/config.yml /templates/mora.properties.mustache > mora.properties

mora -config mora.properties