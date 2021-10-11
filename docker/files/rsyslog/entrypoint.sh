#!/bin/bash

mustache /config/config.yml /templates/analytics.conf.mustache > /etc/rsyslog.d/analytics.conf
mustache /config/config.yml /templates/rsyslog.conf.mustache > /etc/rsyslog.conf

# run with -n to prevent auto-backgrounding
rsyslogd -n