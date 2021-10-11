FROM node:10.15.3

COPY ./src/js/admin-ui /admin-ui

WORKDIR admin-ui

RUN npm install -g ember-cli@3.8.1
RUN npm install
RUN DEBUG=ember-cli:* ember build
CMD ember serve