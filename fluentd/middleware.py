"""
A Django middleware to forward our request metadata to Elasticsearch (nothing to
do with the NSA):

A very minimalistic Django request log forwarder for a fluentd HTTP endpoint
accepting JSON payloads via POST requests. That's all you need !

Configuration:
--------------

Goes in your django config file, in a FLUENTD_REQUEST_FORWARDER dict, following
the same settings format as Django Rest Framework does.

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

Have fun querying your logs !

TODO: add logging to a module specific logger (that the Django user willing to
know when his fluentd endpoints are flaky should redirect to console output or
other log pipelines where fluentd isn't involved).
TODO: catch exceptions in the payload too
TODO: optionnally log bodies (as JSON if they are of JSON type) of both requests
      and responses, either on error-ish status codes (>= 400) or all the time,
      with a limit on the body size as well maybe

"""

from __future__ import unicode_literals

# stl
import re
import json
import time
import socket
import logging
import threading
from collections import deque
from datetime import datetime

# 3p
import requests
from django.conf import settings
from werkzeug.wrappers import Request
from six.moves.urllib.parse import parse_qs


LOG = logging.getLogger('django_requests_fluentd_forwarder_middleware')


class PushQueue(threading.Thread):
    """
    A minimalistic push queue that buffers our request logs and forwards them to
    fluentd, asynchronously of course (to avoid blocking your backend
    responses).

    Note:
    -----
    Use drop_size and flush_period to to shape the additional memory and CPU
    consumption introduced by this middleware.
    """
    def __init__(self, url, drop_size=1000, flush_period=10, retry_interval=10):
        """
        Parameters:
          * url: the fluentd HTTP URL to post payloads to (https isn't supported
                 for now)
          * drop_size: start dropping payloads if they can't be flushed when
                       len(payloads) > drop_size
          * flush_period: time between two full-flushes of the push queue
        """
        threading.Thread.__init__(self)
        self.url = url
        self.flush_period = flush_period
        self.retry_interval = retry_interval

        self._payloads = deque(maxlen=drop_size)

        self.start()

    def append_payload(self, payload):
        """
        Appends a (dict) payload string to the push queue.
        """
        LOG.debug('Enqueuing payload: %s', json.dumps(payload))
        self._payloads.appendleft(payload)

    def run(self):
        while True:
            # While we have elements to flush
            flush_start = time.time()
            while self._payloads:
                payload = self._payloads.pop()

                try:
                    LOG.debug('Forwarding payload: %s', json.dumps(payload))
                    req = requests.post(
                        self.url, data={'json': json.dumps(payload)}
                    )
                    req.raise_for_status()
                except requests.exceptions.RequestException as err:
                    # Let's put our payload back in the queue, we'll try again
                    # later
                    LOG.warning('Error forwarding payload: %s', err)
                    self._payloads.append(payload)
                    time.sleep(self.retry_interval)

            time.sleep(max(0, self.flush_period - (time.time() - flush_start)))


class DjangoRequestLoggingMiddleware(object):
    """
    A Django middleware that logs all requests to a fluentd HTTP endpoint.
    """
    def __init__(self):
        """ Builds the middleware, inits the push queue """
        conf = settings.FLUENTD_REQUEST_FORWARDER

        self.fluentd_env = conf.get('ENV', None)

        host = conf.get('HOST', 'localhost')
        port = conf.get('PORT', '24224')
        tag = conf.get('TAG', 'django.requests')

        self._push_queue = PushQueue(
            "http://{0}:{1}/{2}".format(host, port, tag),
            int(conf.get('DROP_SIZE', '10000')),
            float(conf.get('FLUSH_PERIOD', '10')),
            float(conf.get('RETRY_INTERVAL', '10'))
        )

    def process_request(self, request):
        """ Called when a request is initiated """
        request.META['timestamp_started'] = datetime.utcnow()
        request.META['request'] = Request(request.META)

    def request_header_size(self, request):
        """ Computes the size of request headers """
        # {METHOD} {URL} HTTP/1.1\r\n = 12 extra characters for space between
        # method and url, and ` HTTP/1.1\r\n`
        first_line = len(request.META.get('REQUEST_METHOD')) + \
                     len(request.get_full_path()) + \
                     12

        # {KEY}: {VALUE}\n\r = 4 extra characters for `: ` and `\n\r` minus
        # `HTTP_` in the KEY is -1
        header_fields = sum([(len(header) + len(value) - 1)
                             for (header, value)
                             in request.META.items()
                             if header.startswith('HTTP_')])

        last_line = 2 # /r/n

        return first_line + header_fields + last_line

    def client_address(self, request):
        """ Determines the original (before proxies) client IP from headers """
        ip = request.META.get('HTTP_X_FORWARDED_FOR',
                              request.META.get('REMOTE_ADDR', None))
        if ip:
            return ip.split(',')[0]

    def response_header_size(self, response):
        """ Computes the size of response headers """
        # HTTP/1.1 {STATUS} {STATUS_TEXT} = 10 extra characters
        first_line = len(str(response.status_code)) + \
                     len(response.reason_phrase) + \
                     10

        # {KEY}: {VALUE}\n\r = 4 extra characters `: ` and `\n\r`
        header_fields = sum([(len(header) + len(value) + 4)
                             for (header, value)
                             in response._headers.items()])

        return first_line + header_fields

    def process_response(self, request, response):
        """ Called before the response is sent to the client """
        started_datetime = request.META.get('timestamp_started',
                                            datetime.utcnow())

        # <3 dict comprehensions :)
        request_headers = {re.sub('^HTTP_', '', header): value.lower()
                           for (header, value)
                           in request.META.items()
                           if header.startswith('HTTP_')}

        request_headers_size = self.request_header_size(request)

        request_query_string = [
            {
                'name': name,
                'value': (value[0] if len(value) > 0 else None)
            }
            for name, value
            in parse_qs(request.META.get('QUERY_STRING', '')).items()]

        req = request.META.get('request')
        request_content_size = req.content_length or 0

        response_headers = response._headers

        response_headers_size = self.response_header_size(response)
        response_content_size = len(response.content)

        payload = {
            'fluentd_env': self.fluentd_env,
            'time_started': started_datetime.isoformat() + 'Z',
            'server_ip': socket.gethostbyname(socket.gethostname()),
            'x_client_address': self.client_address(request),
            'time': int(
                round((datetime.utcnow() - started_datetime).total_seconds() *
                      1000)),
            'request': {
                'method': request.method,
                'url': request.build_absolute_uri(),
                'http_version': 'HTTP/1.1',
                'query_string': request_query_string,
                'headers': request_headers,
                'headers_size': request_headers_size,
                'content': {
                    'size': request_content_size,
                    'mime_type': request.META.get('CONTENT_TYPE',
                                                  'application/octet-stream')
                },
                'body_size': request_content_size,
            },
            'response': {
                'status': response.status_code,
                'status_text': response.reason_phrase,
                'http_version': 'HTTP/1.1',
                'headers': response_headers,
                'headers_size': response_headers_size,
                'content': {
                    'size': response_content_size,
                    'mime_type': response._headers.get(
                        'content-type', (None, 'application/octet-stream'))[-1]
                },
                'body_size': response_headers_size + response_content_size,
                'redirect_url': response._headers.get(
                    'location', ('location', '')
                )[-1]
            },
        }

        self._push_queue.append_payload(payload)

        return response
