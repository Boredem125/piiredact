"""Send text to an AI without the personal data in it, then map the answer back.

    python examples/ai_round_trip.py            # offline, with a stand-in AI
    python examples/ai_round_trip.py --claude   # a real call (pip install anthropic)

The table that links "Person A" to the real name stays in this process. Only
the masked text goes to the AI.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator

import depii

TICKET = (
    "Customer Aryan Mehta (aryan.mehta@example.com, +91 98765 43210) says his "
    "neighbour Ravan Kapoor keeps parking in his slot at 42 MG Road, Pune. "
    "Aryan wants a polite note he can send to Ravan."
)


def fake_ai(prompt: str) -> Iterator[str]:
    """Stands in for a model: writes a reply that uses the labels it was given."""
    reply = (
        "Dear Person B,\n\nI hope you're well. Person A asked me to mention that the "
        "parking slot at Address A is reserved for Person A's household. Could you "
        "use the visitor bays instead? Person A can be reached at Email A or Phone A "
        "if you'd like to talk it over.\n\nKind regards"
    )
    # Arrive in small pieces, as a streaming API would.
    for start in range(0, len(reply), 7):
        yield reply[start : start + 7]


def claude(system: str, messages: list[dict[str, object]]) -> Iterator[str]:
    """Stream a reply from Claude. Needs `pip install anthropic` and credentials."""
    import anthropic

    client = anthropic.Anthropic()
    with client.messages.stream(
        model="claude-opus-5-5",
        max_tokens=64000,
        system=system,
        messages=messages,
    ) as stream:
        yield from stream.text_stream


def main() -> None:
    p = depii.Pseudonymizer()  # one per conversation

    history = [{"role": "user", "content": TICKET + "\nPlease draft that note."}]
    masked = p.mask_messages(history)
    print("Sent to the AI:\n ", masked[0]["content"], "\n")

    if "--claude" in sys.argv:
        chunks = claude(p.instructions, masked)
    else:
        chunks = fake_ai(str(masked[0]["content"]))

    print("Shown to the user (unmasked as it streams):\n")
    for piece in p.unmask_stream(chunks):
        print(piece, end="", flush=True)
    print("\n")

    # The table never leaves this process. Print it here only to show it.
    print("Table kept locally:", p.table)


if __name__ == "__main__":
    main()
