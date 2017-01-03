Django Request Logger for FLuentD-HTTP
======================================

Logs Django requests and response metadata as well as the request and response
bodies in case an error (4xx or 5xx) is triggered and the exception thrown by
Django if exception there is.

Theses logs are formatted as JSON for a better compliance with modern document
indexing and processing solutions (who said Elasticseach ?).

All you have to do is setup a fluentd HTTP receiver and adapt the configuration
in Django accordingly (that simply goes in your traditionnal Django
`settings.py` file):

```shell
 * FLUENTD_HOST: fluentd server hostname (default: localhost)
 * FLUENTD_PORT: fluentd http server port (default: 24224)
 * FLUENTD_ENV : adds an "environment" tag to log document (default: None)
 * FLUENTD_TAG : tag identyfing the source in fluentd pipelines (default
                 django.requests)
```
