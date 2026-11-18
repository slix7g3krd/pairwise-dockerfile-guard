from security.dockerfile_guard import (
    parse_instructions,
    is_non_root,
    base_digest,
    has_secret_arg,
    is_safe_install,
    capabilities_ok,
    dockerignore_ok,
    entry_permissions
)


def test_root():
    assert is_non_root('USER root') is False

def test_nonroot():
    assert is_non_root('USER app') is True

def test_latest():
    assert base_digest('FROM python:latest') is False

def test_digest():
    assert base_digest('FROM python@sha256:abc') is True

def test_secret():
    assert has_secret_arg('ARG API_KEY=x') is True

def test_install():
    assert is_safe_install('RUN curl https://x | sh') is False

def test_apt():
    assert is_safe_install('RUN apt-get install -y x && rm -rf /var/lib/apt/lists/*') is True

def test_caps():
    assert capabilities_ok({'cap_add': ['ALL']}) is False

def test_health():
    assert parse_instructions('FROM x\nHEALTHCHECK CMD true')['HEALTHCHECK'] is True

def test_multi():
    assert parse_instructions('FROM builder AS build\nFROM runtime')['stages'] == 2

def test_ignore():
    assert dockerignore_ok('.git') is False

def test_entry():
    assert entry_permissions(755) is False

def test_empty():
    assert parse_instructions('') == {}

def test_setuid():
    assert is_safe_install('RUN chmod u+s /bin/x') is False

def test_safe():
    assert has_secret_arg('ARG NAME=x') is False
