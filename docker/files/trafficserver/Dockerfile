FROM debian:11.0 as build

RUN apt-get update
RUN apt-get install -y wget
RUN apt-get install -y git

# install mustache cli for creating the config
COPY ./docker/files/install-mustache-cli.sh /temp/install-mustache-cli.sh
RUN /temp/install-mustache-cli.sh

RUN git clone https://luajit.org/git/luajit.git
RUN git clone https://git-wip-us.apache.org/repos/asf/trafficserver.git

FROM debian:11.0

RUN apt-get update
RUN apt-get install -y autoconf
RUN apt-get install -y automake
RUN apt-get install -y pkg-config
RUN apt-get install -y libtool
RUN apt-get install -y libpcre3 libpcre3-dev
RUN apt-get install -y libpcap0.8
RUN apt-get install -y flex
RUN apt-get install -y hwloc
RUN apt-get install -y lua5.4
RUN apt-get install -y zlib1g
RUN apt-get install -y zlib1g-dev
RUN apt-get install -y libncurses5-dev libncursesw5-dev
RUN apt-get install -y curl
RUN apt-get install -y build-essential
RUN apt-get install -y libssl-dev

COPY --from=build /opt/mustache/mustache /usr/local/bin/mustache
COPY --from=build /trafficserver /trafficserver
COPY --from=build /luajit /luajit

WORKDIR /luajit
RUN make install PREFIX=/opt/luajit

WORKDIR /trafficserver
RUN autoreconf -if
RUN ./configure --prefix=/opt/ts --with-luajit="/opt/luajit"
RUN make
RUN make install

COPY ./config/default.yml /config/config.yml
COPY ./templates/etc/trafficserver /templates/

# copy entrypoint
COPY ./docker/files/trafficserver/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]