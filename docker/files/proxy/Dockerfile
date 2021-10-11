FROM openresty/openresty:1.19.9.1-1-buster-fat as build

ARG MAXMIND_LICENSE_KEY_ARG
ARG MAXMIND_EDITION_ID_ARG=GeoLite2-City
ARG MAXMIND_DOWNLOAD_URL_ARG=https://download.maxmind.com/app/geoip_download

ENV MAXMIND_LICENSE_KEY=$MAXMIND_LICENSE_KEY_ARG
ENV MAXMIND_EDITION_ID=$MAXMIND_EDITION_ID_ARG
ENV MAXMIND_DOWNLOAD_URL=$MAXMIND_DOWNLOAD_URL_ARG

ENV NOKOGIRI_USE_SYSTEM_LIBRARIES 1

COPY ./src/lua/auto-ssl /opt/api-umbrella/src/api-umbrella/auto-ssl
COPY ./src/lua/cli /opt/api-umbrella/src/api-umbrella/cli
COPY ./src/lua/elasticsearch-aws-signing-proxy /opt/api-umbrella/src/api-umbrella/elasticsearch-aws-signing-proxy
COPY ./src/lua/http-api /opt/api-umbrella/src/api-umbrella/http-api
COPY ./src/lua/proxy /opt/api-umbrella/src/api-umbrella/proxy
COPY ./src/lua/utils /opt/api-umbrella/src/api-umbrella/utils
COPY ./src/lua/cli.lua /opt/api-umbrella/src/api-umbrella/cli.lua
COPY ./src/lua/conf.lua /opt/api-umbrella/src/conf.lua

COPY ./bin /opt/api-umbrella/bin
COPY ./build /opt/api-umbrella/build
COPY ./templates/etc/nginx /opt/api-umbrella/templates/etc/nginx
COPY ./templates/etc/perp /opt/api-umbrella/templates/etc/perp
COPY ./tasks /opt/api-umbrella/tasks
COPY ./Taskfile.yml /opt/api-umbrella/Taskfile.yml
COPY ./Makefile.in /opt/api-umbrella/Makefile.in
COPY ./configure /opt/api-umbrella/configure

WORKDIR /opt/api-umbrella

RUN ./tasks/install-system-build-dependencies
RUN ./configure

RUN if [[ -n "$MAXMIND_LICENSE_KEY_ARG" ]] ; then make deps:geolitecity ; else echo "If you want to use the geoIp-feature, please provide a valid license key." ; fi

RUN echo "Install dependencies"
RUN make deps && make clean:dev

RUN echo "Install app dependencies"
RUN make app-deps && make clean:dev

RUN echo "Make all"
RUN make && make clean:dev

RUN groupadd -r api-umbrella && \
  useradd -r -g api-umbrella -s /sbin/nologin -d /opt/api-umbrella -c "API Umbrella user" api-umbrella

ENV API_UMBRELLA_ROOT /opt/api-umbrella
ENV API_UMBRELLA_SRC_ROOT /opt/api-umbrella
ENV PATH "/opt/api-umbrella/bin:${PATH}"

COPY ./config/ /opt/api-umbrella/config/

RUN mkdir /opt/api-umbrella/etc
RUN mkdir /opt/api-umbrella/var

# required for nginx error logs
RUN mkdir /opt/api-umbrella/logs
RUN mkdir /opt/api-umbrella/var/log
RUN mkdir /opt/api-umbrella/var/run
RUN mkdir /opt/api-umbrella/var/tmp
RUN mkdir /opt/api-umbrella/var/db

CMD ["api-umbrella", "run"]