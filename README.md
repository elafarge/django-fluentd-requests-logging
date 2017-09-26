Django Request Logger for FluentD-HTTP
======================================

DEPRECATION NOTICE
------------------

**This project won't be maintained anymore**, you can consider alternatives such
as [django-logging-json](https://github.com/cipriantarta/django-logging). Which
is much better anyways. I won't be writing a single line of code for Django
anymore :)

Logs Django requests and response metadata as well as the request and response
bodies optionally.

Theses logs are formatted as JSON for a better compliance with modern document
indexing and processing solutions (who said Elasticseach ?).

All you have to do is setup a fluentd HTTP receiver and adapt the configuration
in Django accordingly (that simply goes in your traditionnal Django
`settings.py` file):

```shell
 * HOST: fluentd server hostname (default: localhost)
 * PORT: fluentd http server port (default: 24224)
 * ENV : adds a "fluentd_environment" tag to log document (default: None)
 * TAG : tag identifying the source in fluentd pipelines (default
         django.requests)
 * FLUSH_PERIOD: the interval between two flushes of the fluentd push queue
                 (allows for CPU consumption shaping)
 * DROP_SIZE: when there are more logs that DROP_SIZE in the push queue, older
              logs will be flushed
 * RETRY_INTERVAL: time to wait before trying again a failed request
 * IGNORE_REQUESTS: (Python) list of (method, path, response_code) tuples for
                    which not to forward requests (useful for health checks for
                    instance)
 * FIELDS_TO_OBFUSCATE: a Python list of fields (such as
                        "requests.headers.authorization" to obfuscate. Passwords
                        and API keys mostly ;-) The value of these fields will
                        be replaced with "OBFUSCATED" before anything is
                        forwarded to fluentd.
```

License
-------
MIT

Maintainers
-----------
 * Etienne Lafarge <etienne@rythm.co>
