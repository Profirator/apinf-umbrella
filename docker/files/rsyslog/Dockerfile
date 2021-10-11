FROM debian:11.0 as build

RUN apt-get update
RUN apt-get install -y wget

# install mustache cli for creating the config
COPY ./docker/files/install-mustache-cli.sh /temp/install-mustache-cli.sh
RUN /temp/install-mustache-cli.sh

FROM debian:11.0-slim

COPY --from=build /opt/mustache/mustache /usr/local/bin/mustache

# install rsyslog
RUN apt-get update
RUN apt-get install -y rsyslog

# copy in default config and config template
COPY ./config/default.yml /config/config.yml
COPY ./templates/etc/rsyslog.d/analytics.conf.mustache /templates/analytics.conf.mustache
COPY ./templates/etc/rsyslog.conf.mustache /templates/rsyslog.conf.mustache

# copy entrypoint
COPY ./docker/files/rsyslog/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

