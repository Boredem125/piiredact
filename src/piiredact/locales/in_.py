"""India identifiers. The module is ``in_`` because ``in`` is a keyword."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<![A-Za-z0-9])"
_R = r"(?![A-Za-z0-9])"

# Payment service provider handles registered with NPCI. A handle from this
# list is what separates a UPI ID from any other ``name@word`` string.
_UPI_HANDLES = (
    "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl", "paytm", "ptyes",
    "ptaxis", "pthdfc", "ptsbi", "upi", "apl", "yapl", "rapl", "abfspay", "fam", "ikwik",
    "jupiteraxis", "naviaxis", "slice", "superyes", "timecosmos", "waaxis", "wahdfcbank",
    "waicici", "wasbi", "freecharge", "airtel", "jio", "postbank", "axisbank", "hdfcbank",
    "icici", "sbi", "kotak", "barodampay", "pnb", "unionbank", "cnrb", "idfcbank", "indus",
    "yesbank", "federal", "rbl", "aubank", "dbs", "hsbc", "sc", "citi", "boi", "mahb",
    "idbi", "uco", "kvb", "tmb", "dlb", "csbpay", "equitas", "ujjivan", "fbl", "pingpay",
    "payzapp", "myicici", "axisb", "pockets", "imobile", "kmbl", "zoicici", "goaxb",
)  # fmt: skip

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "IN_AADHAAR",
        r"(?<!\w)(?<!\w[.-])[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?!\w)(?!-\w)",
        score=0.6,
        validator=v.in_aadhaar,
        context=("aadhaar", "aadhar", "adhaar", "adhar", "uid", "uidai", "आधार"),
    ),
    PatternDetector(
        "IN_PAN",
        _L + r"[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]" + _R,
        score=0.85,
        context=("pan", "pan no", "pan number", "pan card", "permanent account number"),
    ),
    PatternDetector(
        "IN_GSTIN",
        _L + r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]" + _R,
        score=0.95,
        validator=v.in_gstin,
        context=("gstin", "gst", "gst no", "gst number"),
    ),
    PatternDetector(
        "IN_VOTER_ID",
        _L + r"[A-Z]{3}\d{7}" + _R,
        score=0.5,
        context=("voter", "voter id", "epic", "epic no", "election card", "मतदाता"),
        require_context=True,
    ),
    PatternDetector(
        "IN_PASSPORT",
        _L + r"[A-PR-WY][1-9]\d{6}" + _R,
        score=0.5,
        context=("passport", "passport no", "passport number", "पासपोर्ट"),
        require_context=True,
    ),
    PatternDetector(
        "IN_IFSC",
        _L + r"[A-Z]{4}0[A-Z0-9]{6}" + _R,
        score=0.6,
        context=("ifsc", "ifsc code", "neft", "rtgs", "imps", "branch"),
    ),
    PatternDetector(
        "IN_UPI_ID",
        r"(?<!\w)(?<!\w[.+%-])[A-Za-z0-9][A-Za-z0-9._-]{1,255}@(?:"
        + "|".join(_UPI_HANDLES)
        + r")(?!\w)(?!-\w)(?!\.\w)",
        score=0.9,
        context=("upi", "vpa", "upi id", "gpay", "phonepe", "bhim"),
    ),
    PatternDetector(
        "IN_UPI_ID",
        r"(?<!\w)(?<!\w[.+%-])[A-Za-z0-9][A-Za-z0-9._-]{1,255}@[A-Za-z]{2,32}(?!\w)(?!-\w)(?!\.\w)",
        name="in_upi_id_unknown_handle",
        score=0.5,
        context=("upi", "vpa", "upi id", "gpay", "phonepe", "bhim"),
        require_context=True,
    ),
    PatternDetector(
        "IN_PIN_CODE",
        r"(?<!\w)(?<!\w[.-])[1-9]\d{2} ?\d{3}(?!\w)(?!-\w)",
        score=0.4,
        context=("pin", "pincode", "pin code", "postal code", "पिन"),
        require_context=True,
    ),
)
