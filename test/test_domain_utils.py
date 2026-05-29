import pytest

from network.recon.domain_utils import extract_domain


def test_full_url_with_path():
    result = extract_domain("https://sv.wikipedia.org/wiki/Instabox")
    assert result["subdomain"] == "sv"
    assert result["domain"] == "wikipedia"
    assert result["suffix"] == "org"
    assert result["registered_domain"] == "wikipedia.org"
    assert result["input"] == "https://sv.wikipedia.org/wiki/Instabox"


def test_bare_domain():
    result = extract_domain("wikipedia.org")
    assert result["subdomain"] == ""
    assert result["domain"] == "wikipedia"
    assert result["suffix"] == "org"
    assert result["registered_domain"] == "wikipedia.org"


def test_url_with_subdomain():
    result = extract_domain("https://mail.google.com")
    assert result["subdomain"] == "mail"
    assert result["domain"] == "google"
    assert result["suffix"] == "com"
    assert result["registered_domain"] == "google.com"


def test_url_with_no_subdomain():
    result = extract_domain("https://github.com/trending")
    assert result["subdomain"] == ""
    assert result["domain"] == "github"
    assert result["suffix"] == "com"
    assert result["registered_domain"] == "github.com"
