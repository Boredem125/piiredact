import io
import logging

import pytest

from depii import Mask, PIIFilter, Redactor
from depii.logfilter import FAILED


@pytest.fixture
def log():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    handler.addFilter(PIIFilter())
    logger = logging.getLogger("depii-test")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    yield logger, stream
    logger.handlers.clear()


def test_message_and_arguments(log):
    logger, stream = log
    logger.info("login by %s from %s", "jane@example.com", "203.0.113.9")
    assert stream.getvalue() == "INFO login by [EMAIL] from [IP_ADDRESS]\n"


def test_dict_arguments(log):
    logger, stream = log
    logger.info("user %(mail)s", {"mail": "jane@example.com"})
    assert stream.getvalue() == "INFO user [EMAIL]\n"


def test_exception_text(log):
    logger, stream = log
    try:
        raise ValueError("bad address jane@example.com")
    except ValueError:
        logger.exception("failed for 078-05-1120")
    out = stream.getvalue()
    assert "jane@example.com" not in out and "078-05-1120" not in out
    assert "ValueError: bad address [EMAIL]" in out
    assert "failed for [US_SSN]" in out


def test_stack_info(log):
    logger, stream = log
    logger.info("where jane@example.com", stack_info=True)
    assert "jane@example.com" not in stream.getvalue()


def test_extra_fields():
    record_holder = []

    class Capture(logging.Handler):
        def emit(self, record):
            record_holder.append(record)

    handler = Capture()
    handler.addFilter(PIIFilter())
    logger = logging.getLogger("depii-test-extra")
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.warning("x", extra={"contact": "jane@example.com", "password": "hunter2", "n": 3})
    record = record_holder[0]
    assert (record.contact, record.password, record.n) == ("[EMAIL]", "[SECRET]", 3)


def test_custom_redactor(log):
    logger, stream = log
    logger.handlers[0].filters[:] = [PIIFilter(Redactor(default_operator=Mask(keep_last=4)))]
    logger.info("card 4111 1111 1111 1111")
    assert stream.getvalue() == "INFO card **** **** **** 1111\n"


def test_failure_withholds_the_message(log):
    logger, stream = log

    class Broken(Redactor):
        def redact(self, text):
            raise RuntimeError("boom")

    logger.handlers[0].filters[:] = [PIIFilter(Broken())]
    logger.info("secret jane@example.com")
    assert stream.getvalue() == f"INFO {FAILED}\n"


def test_bad_format_arguments_do_not_leak(log):
    logger, stream = log
    logger.info("only one %s", "jane@example.com", "extra")
    assert "jane@example.com" not in stream.getvalue()
