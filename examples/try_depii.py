"""A quick tour of depii. Run it with:  python examples/try_depii.py

Every value below is made up: example.com addresses, 555-01xx phone
numbers, published test card numbers and generated IDs.
"""

import io
import logging
import sys

import depii
from depii import Hash, Mask, PIIFilter, Redactor, Tokenize, Vault

# Some consoles (older Windows ones) cannot show every script used below.
# Print a placeholder for those characters instead of stopping.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


section("1. One call")
text = (
    "Hi, I'm Jane. Mail jane.doe@example.com or call +1 415 555 0132. "
    "Card 4111 1111 1111 1111, SSN 078-05-1120, server 203.0.113.42."
)
print("in: ", text)
print("out:", depii.redact(text))

section("2. What was found (values are not printed by repr)")
for span in depii.scan(text):
    print(f"  {span.entity:12s} at {span.start:3d}-{span.end:<3d} score {span.score:.2f}  {span!r}")

section("3. Country identifiers")
samples = [
    "Aadhaar 2345 6789 0124, PAN ABCPE1234F, GSTIN 27AAPFU0939F1ZV, pay raj@okaxis",
    "NINO AB123456C, NHS number 943 476 5919, postcode SW1A 1AA",
    "IBAN DE89 3704 0044 0532 0130 00, Steuer-ID 86095742719, DNI 12345678Z",
    "Codice fiscale RSSMRA80A01H501U, BSN 111222333",
    # countries added in 0.2
    "CPF 529.982.247-25, RUT 12.345.678-5, SIN 130 692 544",
    "NRIC S1234567D, 身份证 11010519491231002X, RRN 900101-1234567",
    "PESEL 44051401359, personnummer 811228-9874, AHV 756.9217.0769.85",
    "ABN 51 824 753 556, SA ID 8001015009087, Emirates ID 784-1968-6570305-0",
]
for sample in samples:
    print("  " + depii.redact(sample))

section("4. Choosing how values are replaced")
redactor = Redactor(
    policy={
        "CREDIT_CARD": Mask(keep_last=4),
        "EMAIL": Hash("demo-key-please-use-a-real-secret"),
    }
)
print("  " + redactor.redact("jane@example.com paid with 4111 1111 1111 1111").text)

section("5. Reversible tokens")
vault = Vault()
tokenizer = Redactor(default_operator=Tokenize(vault))
masked = tokenizer.redact("From a@example.com to b@example.com, cc a@example.com").text
print("  tokenized:", masked)
print("  restored: ", vault.restore(masked))

section("6. Nested data: field names count too")
record = {
    "user": {"firstName": "Jane", "password": "hunter2", "phone": 4155550132},
    "note": "Contact jane@example.com about ticket 4021",
    "tags": ["vip", "203.0.113.7"],
}
print("  ", depii.redact_obj(record))

section("7. Logging")
stream = io.StringIO()
handler = logging.StreamHandler(stream)
handler.addFilter(PIIFilter())
logger = logging.getLogger("demo")
logger.addHandler(handler)
logger.propagate = False
logger.warning("login failed for %s from %s", "jane@example.com", "198.51.100.9")
print("  " + stream.getvalue().strip())

section("8. Strict mode catches bare numbers that need context otherwise")
loose = "ref 078051120"
print("  default:", depii.redact(loose))
print("  strict: ", depii.redact(loose, strict=True))

section("9. Things it leaves alone")
for clean in [
    "Order 1234567890 shipped on 2024-03-15 at 14:32:07",
    "Upgrade to version 11.2.0, see https://example.com/docs",
    "commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
]:
    print("  " + depii.redact(clean))

print(f"\ndepii {depii.__version__}: {len(depii.supported_entities())} entity types")
