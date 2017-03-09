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
 * IGNORE_REQUESTS: (Python) list of (method, path, response_code) tuples for
                    which not to forward requests (useful for health checks for
                    instance)
 * FIELDS_TO_OBFUSCATE: a Python list of fields (such as
                        "requests.headers.authorization" to obfuscate. Passwords
                        and API keys mostly ;-) The value of these fields will
                        be replaced with "OBFUSCATED" before anything is
                        forwarded to fluentd.

Have fun querying your logs !
"""

from __future__ import unicode_literals

# stl
import re
import sys
import json
import time
import base64
import socket
import logging
import threading
import traceback
from collections import deque
from datetime import datetime

# 3p
import requests
from werkzeug.wrappers import Request
from six.moves.urllib.parse import parse_qs
from django.conf import settings
try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    class MiddlewareMixin(object):
        """
        Blank class for older versions of Django where MiddlewareMixin
        doesn't exist
        """
        def __init__(self, get_response):
            pass


# Constants + logging handle
LOG_ALL_BODIES = 2
LOG_BODIES_ON_ERRORS = 1
LOG_NO_BODY = 0
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
        self.setDaemon(True)

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


class DjangoRequestLoggingMiddleware(MiddlewareMixin):
    """
    A Django middleware that logs all requests to a fluentd HTTP endpoint.
    """
    def __init__(self, get_response=None):
        """ Builds the middleware, inits the push queue """
        MiddlewareMixin.__init__(self, get_response)
        conf = settings.FLUENTD_REQUEST_FORWARDER

        self.fluentd_env = conf.get('ENV', None)
        self.body_log_policy = conf.get('BODY_LOG_POLICY', LOG_NO_BODY)
        self.max_body_log_size = conf.get('MAX_BODY_LOG_SIZE', 1000)

        host = conf.get('HOST', 'localhost')
        port = conf.get('PORT', '24224')
        tag = conf.get('TAG', 'django.requests')

        self.ignore_map = {path: (method.lower(), expected_status)
                           for (method, path, expected_status)
                           in conf.get('IGNORE_REQUESTS', [])}

        self.fields_to_obfuscate = conf.get('FIELDS_TO_OBFUSCATE', [])

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

        # Should we log the baby
        if self.body_log_policy in [LOG_ALL_BODIES, LOG_BODIES_ON_ERRORS]:
            request.META['body'] = request.body

    def process_exception(self, request, exception):
        """ Called when an exception occurs in the view """
        exc_type, exc_value, exc_traceback = sys.exc_info()
        request.META['exception'] = traceback.format_exception(
            exc_type, exc_value, exc_traceback
        )

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

    def obfuscate_basicauth_password(self, headers):
        if "authorization" in headers and \
                headers["authorization"].startswith("Basic "):
            auth_string = headers["authorization"].replace("Basic ", "")
            try:
                authlist = base64.b64decode(auth_string.decode("utf-8")) \
                                 .split(":", 1)
                headers["authorization"] = authlist[0] + ":" + \
                                           "*" * len(authlist[1])
            except UnicodeDecodeError:
                pass

        return headers

    def build_body_log(self, body_text):
        """
        Builds the body log (truncates it if it exceeds max_body_log_size,
        returns a dict if the body is JSON-readable...)
        """
        if len(body_text) > self.max_body_log_size:
            body_log = body_text[:self.max_body_log_size]
        else:
            body_log = body_text

        return body_log

    def process_response(self, request, response):
        """ Called before the response is sent to the client """
        # (METHOD, PATH, HTTP STATUS CODE) is to be ignored ? Bye !
        req_path = request.get_full_path()
        if req_path in self.ignore_map:
            (verb, code) = self.ignore_map[req_path]

            if request.method.lower() == verb and response.status_code == code:
                return response

        started_datetime = request.META.get('timestamp_started',
                                            datetime.utcnow())

        # <3 dict comprehensions :)
        request_headers = {re.sub('^HTTP_', '', header).lower(): value
                           for (header, value)
                           in request.META.items()
                           if header.startswith('HTTP_')}

        request_headers_size = self.request_header_size(request)

        request_headers = self.obfuscate_basicauth_password(request_headers)

        request_query_string = [
            {
                'name': name,
                'value': (value[0] if len(value) > 0 else None)
            }
            for name, value
            in parse_qs(request.META.get('QUERY_STRING', '')).items()]

        req = request.META.get('request')
        request_content_size = req.content_length \
                               if req and req.content_length \
                               else 0

        response_headers = {name: values[1:]
                            for (name, values)
                            in response._headers.items()}

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
                'path': request.get_full_path(),
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

        # Log bodies as well if required
        if self.body_log_policy == LOG_ALL_BODIES \
                or self.body_log_policy == LOG_BODIES_ON_ERRORS \
                and response.status_code >= 400:
            try:
                payload['request']['body'] = \
                    self.build_body_log(request.META.get('body')
                                        .decode('utf-8'))
            except UnicodeDecodeError:
                payload['request']['body'] = "Error decoding body to utf-8"

            try:
                payload['response']['content']['value'] = \
                    self.build_body_log(response.content.decode('utf-8'))
            except UnicodeDecodeError:
                payload['response']['content']['value'] = "Error decoding " \
                    "body to utf-8"

        # Obfuscate sensitive fields on the app owner's behalf
        def recobfs(tree, obfuscated_path):
            key = obfuscated_path.split('.')
            if len(key) > 1:
                recobfs(tree[key[0]], '.'.join(key[1::]))
            else:
                tree[key[0]] = "OBFUSCATED!"

        for sensifield in self.fields_to_obfuscate:
            recobfs(payload, sensifield)

        self._push_queue.append_payload(payload)

        return response
