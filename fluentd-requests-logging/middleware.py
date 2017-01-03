"""
A Django middleware to forward our request metadata to Elasticsearch (nothing to
do with the NSA):

A very minimalistic Django request log forwarder for a fluentd HTTP endpoint
accepting JSON payloads via POST requests. That's all you need !

Configuration (goes in your django config file ;-) )
----------------------------------------------------

 * FLUENTD_HOST: fluentd server hostname (default: localhost)
 * FLUENTD_PORT: fluentd http server port (default: 24224)
 * FLUENTD_ENV : adds an "environment" tag to log document (default: None)
 * FLUENTD_TAG : tag identyfing the source in fluentd pipelines (default
                 django.requests)

Have fun querying your logs !

TODO: add logging to a module specific logger (that the Django user willing to
know when his fluentd endpoints are flaky should redirect to console output or
other log pipelines where fluentd isn't involved).

"""

from __future__ import unicode_literals

# stl
import re
import socket
from datetime import datetime

# 3p
from django.conf import settings
from werkzeug.wrappers import Request
from six.moves.urllib.parse import parse_qs


class DjangoMiddleware(object):

  def __init__(self):
    self.fluentd_env = getattr(settings, 'FLUENTD_ENV', None)
    self.fluentd_host = getattr(settings, 'FLUENTD_HOST', 'localhost')
    self.fluentd_port = getattr(settings, 'FLUENTD_PORT', '24224')
    self.fluentd_tag = getattr(settings, 'FLUENTD_TAG', 'django.requests')
    self.fluentd_url = "http://%{0}:%{1}/django.requests".format(
        self.fluentd_host, self.fluentd_port, self.fluentd_tag
    )

  def process_request(self, request):
    request.META['timestamp_started'] = datetime.utcnow()
    request.META['request'] = Request(request.META)

  def request_header_size(self, request):
    # {METHOD} {URL} HTTP/1.1\r\n = 12 extra characters for space between method and url, and ` HTTP/1.1\r\n`
    first_line = len(request.META.get('REQUEST_METHOD')) + len(request.get_full_path()) + 12

    # {KEY}: {VALUE}\n\r = 4 extra characters for `: ` and `\n\r` minus `HTTP_` in the KEY is -1
    header_fields = sum([(len(header) + len(value) - 1) for (header, value) in request.META.items() if header.startswith('HTTP_')])

    last_line = 2 # /r/n

    return first_line + header_fields + last_line

  def client_address(self, request):
    ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', None))

    if ip:
      return ip.split(',')[0]

  def response_header_size(self, response):
    # HTTP/1.1 {STATUS} {STATUS_TEXT} = 10 extra characters
    first_line = len(str(response.status_code)) + len(response.reason_phrase) + 10

    # {KEY}: {VALUE}\n\r = 4 extra characters `: ` and `\n\r`
    header_fields = sum([(len(header) + len(value) + 4) for (header, value) in response._headers.items()])

    return first_line + header_fields

  def process_response(self, request, response):
    started_datetime = request.META.get('timestamp_started', datetime.utcnow())

    request_headers = [{'name': re.sub('^HTTP_', '', header), 'value': value} for (header, value) in request.META.items() if header.startswith('HTTP_')]
    request_header_size = self.request_header_size(request)
    request_query_string = [{'name': name, 'value': (value[0] if len(value) > 0 else None)} for name, value in parse_qs(request.META.get('QUERY_STRING', '')).items()]

    r = request.META.get('request')
    request_content_size = r.content_length or 0

    response_headers = [{'name': header, 'value': value[-1]} for (header, value) in response._headers.items()]
    response_headers_size = self.response_header_size(response)
    response_content_size = len(response.content)

    payload = {
      'time_started': started_datetime.isoformat() + 'Z',
      'latency': int(round((datetime.utcnow() - started_date_time).total_seconds() * 1000)),
      'server_ip': socket.gethostbyname(socket.gethostname()),
      'fluentd_env': self.fluentd_env,
      'x_client_address': self.client_address(request),
      'time': int(round((datetime.utcnow() - started_date_time).total_seconds() * 1000)),
      'request': {
        'method': request.method,
        'url': request.build_absolute_uri(),
        'http_version': 'HTTP/1.1',
        'query_string': request_query_string,
        'headers': request_headers,
        'headers_size': request_headers_size,
        'content': {
          'size': request_content_size,
          'mime_type': request.META.get('CONTENT_TYPE', 'application/octet-stream')
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
          'mime_type': response._headers.get('content-type', (None, 'application/octet-stream'))[-1]
        },
        'body_size': response_headers_size + response_content_size,
        'redirect_url': response._headers.get('location', ('location', ''))[-1]
      },
    })

    r = requests.post()

    return response
