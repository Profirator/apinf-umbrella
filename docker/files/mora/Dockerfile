FROM debian:11.0 as build

RUN apt-get update
RUN apt-get install -y wget
RUN apt-get install -y git

# install mustache cli for creating the config
COPY ./docker/files/install-mustache-cli.sh /temp/install-mustache-cli.sh
RUN /temp/install-mustache-cli.sh

# checkout current mora
RUN git clone https://github.com/emicklei/mora.git

FROM golang:1.17.2-alpine3.13

COPY --from=build /opt/mustache/mustache /usr/local/bin/mustache
COPY --from=build /mora /mora

# mustache file for mora config
COPY ./templates/etc/mora.properties.mustache /templates/mora.properties.mustache
# copy in default config
COPY ./config/default.yml /config/config.yml

WORKDIR /mora

# install mora
RUN go get -d -v ./
RUN go install -v ./

# copy entrypoint
COPY ./docker/files/mora/entrypoint.sh /mora/entrypoint.sh

ENTRYPOINT ["/mora/entrypoint.sh"]
