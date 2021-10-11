FROM ruby:2.4.6

RUN apt-get update
RUN apt-get install -y libsass1
RUN apt-get install -y libsass-dev
RUN apt-get install -y nodejs

COPY ./src/ruby/web-app /opt/api-umbrella/src
WORKDIR /opt/api-umbrella/src

RUN bundle update --bundler
RUN bundle config --local without "development:test:assets"
RUN bundle config --local clean true
RUN bundle config --local deployment true
RUN bundle install

ENV API_UMBRELLA_RUNTIME_CONFIG="/config/config.yml"

RUN wget https://github.com/mikefarah/yq/releases/download/v4.2.0/yq_linux_amd64 -O /usr/bin/yq &&\
        chmod +x /usr/bin/yq

COPY ./src/version.txt /opt/api-umbrella/version.txt
COPY ./config/default.yml /config/config.yml

# copy entrypoint
COPY ./docker/files/api/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
