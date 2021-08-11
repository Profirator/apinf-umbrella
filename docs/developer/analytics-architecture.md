# Analytics Architecture

## Overview

Analytics data is gathered on each request made to API Umbrella and logged to a database. The basic flow of how
analytics data gets logged is:

```text
[nginx] => [rsyslog] => [storage database]
```

To explain each step:

-   nginx logs individual request data in JSON format to a local rsyslog server over a TCP socket (using
    [lua-resty-logger-socket](https://github.com/cloudflare/lua-resty-logger-socket)).
-   rsyslog's role in the middle is for a couple of primary purposes:
    -   It buffers the data locally so that if the analytics server is down or requests are coming in too quickly for
        the database to handle, the data can be queued.
    -   It can transform the data and send it to multiple different endpoints.
-   The storage database stores the raw analytics data for further querying or processing.

## Elasticsearch

### Ingest

Data is logged directly to Elasticsearch from rsyslog:

```text
[nginx] ====> [rsyslog] ====> [Elasticsearch]
        JSON            JSON
```

-   rsyslog buffers and sends data to Elasticseach using the Elasticsearch Bulk API.
-   rsyslog's [omelasticsearch](http://www.rsyslog.com/doc/v8-stable/configuration/modules/omelasticsearch.html) output
    module is used.

### Querying

The analytic APIs in the web application directly query Elasticsearch:

```text
[api-umbrella-web-app] => [Elasticsearch]
```

## GeoIP

To capture geographic information about the requesting IP addresses, the [NGINX-GeoIP2 module](https://docs.nginx.com/nginx/admin-guide/dynamic-modules/geoip2/) 
can be used. This module requires a [GeoIP database provided maxmind](https://www.maxmind.com/en/geoip2-databases). In order to comply with 
its license conditions, the feature is deactivated in the default image and no such database is included.

To use the feature, the following steps needs to be done:
* decide on the required [database and license](https://dev.maxmind.com/geoip/geolocate-an-ip?lang=en)
* register a license key
* build the api-umbrella docker image with the command: 
    
    ```docker build -f Dockerfile-build --build-arg MAXMIND_LICENSE_KEY_ARG=<REGISTERED_LICENSE_KEY> --build-arg MAXMIND_EDITION_ID_ARG=<DATABASE_ID> .```
* enable the GeoIP feature in the config:
    ```yaml
    nginx:
      geoip: on
```