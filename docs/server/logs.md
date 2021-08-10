# Log Files

Log files for API Umbrella are stored in `/var/log/api-umbrella/`. Inside that directory you'll find subdirectories for
each process API Umbrella runs. Some of the more relevant log files are highlighted below:

-   `/var/log/api-umbrella/nginx/access.log`: nginx access for all requests log
-   `/var/log/api-umbrella/nginx/current`: nginx error log
-   `/var/log/api-umbrella/web-puma/current`: Log file for the Rails web app (providing the admin and APIs)
-   `/var/log/api-umbrella/trafficserver/access.blog`: Binary log file for the Traffic Server cache server (use
    `/opt/api-umbrella/embedded/bin/traffic_logcat` to view)

# Request logs

3 components of API Umbrella provide a request log:
- trafficserver
- nginx
- rsyslog

In most production systems, not all of them are required. By default, they are enabled. 
The following configuration deactivate the request logs:

**rsyslog**

```yaml
rsyslog:
  disableRequestLogging: true
``` 

**trafficserver**

Trafficserver provides a preconfigured log-format `extended_custom`. They are defined at the [logging.yaml](../../templates/etc/trafficserver/logging.yaml.mustache).
To disable the request logging, no format should be set.

```yaml
trafficserver:
      logFormat:
```

**nginx**

Nginx also provides a preconfigured log-format. Its defined at the [router.conf](../../templates/etc/nginx/router.conf.mustache). 
To disable the request logging, set the access_log_filename configuration should be set to empty.

```yaml
nginx:
    access_log_filename:
```