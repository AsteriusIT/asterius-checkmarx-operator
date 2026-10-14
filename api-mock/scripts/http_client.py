"""HTTP helpers that reject local-file URLs and unsafe redirect schemes."""
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def validate_url(url, schemes):
    parsed = urlsplit(url)
    if (parsed.scheme not in schemes or not parsed.hostname or
            parsed.username is not None or parsed.password is not None):
        raise ValueError("Expected an HTTP(S) URL without embedded credentials")


class RestrictedRedirect(HTTPRedirectHandler):
    def __init__(self, schemes):
        self.schemes = schemes

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, self.schemes)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_http(request, *, timeout, schemes=("https",)):
    url = request.full_url if isinstance(request, Request) else request
    validate_url(url, schemes)
    return build_opener(RestrictedRedirect(schemes)).open(request, timeout=timeout)
