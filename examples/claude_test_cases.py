"""Round-trip test cases against Claude: mask, send, unmask, check.

    python examples/claude_test_cases.py            # needs ANTHROPIC_API_KEY
    python examples/claude_test_cases.py --offline  # show what would be sent

Each case prints the original text, what Claude actually receives, Claude's
reply as it came back (labels only), and the reply with real values put back.
Two checks run on every case: no real value may appear in what is sent, and
any label Claude invented is listed.

Needs `pip install anthropic`. Real calls use a few cents of API credit.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator

import depii

MODEL = "claude-opus-5-5"

CASES: list[dict[str, object]] = [
    {
        "title": "1. Support reply with contact details",
        "turns": [
            "Customer Aryan Mehta (aryan.mehta@example.com, +91 98765 43210) says his "
            "neighbour Ravan Kapoor keeps parking in his slot at 42 MG Road, Pune. "
            "Draft a short, polite note Aryan can send to Ravan."
        ],
    },
    {
        "title": "2. Clinical note summary",
        "turns": [
            "Patient: Priya Sharma, DOB: 14/03/1987, Aadhaar 2345 6789 0124. "
            "Seen by Dr. Kavya Iyer on 2 Oct. Complains of migraines for three weeks; "
            "her husband Rohan Sharma drove her in. Summarise for the referral letter "
            "in three bullet points."
        ],
    },
    {
        "title": "3. Multi-turn conversation, same people again",
        "turns": [
            "Meera Nair manages the Leeds office and Kwame Mensah runs London. "
            "Who should approve travel for a trip between the two offices?",
            "Kwame is on leave next week. Rewrite your answer so Meera approves it, "
            "and mention Kwame by name.",
        ],
    },
    {
        "title": "4. Structured JSON output",
        "json": True,
        "turns": [
            "From this email, return JSON with keys 'sender', 'recipient' and "
            "'callback_number', using the placeholders exactly as they appear. "
            "Return only the JSON.\n\n"
            "Hi Sunita, it's Arjun Rao from accounts. Please call me back on "
            "+44 20 7946 0958 about invoice 4471. Thanks, Arjun"
        ],
    },
    {
        "title": "5. Streaming reply",
        "stream": True,
        "turns": [
            "Write a two-sentence welcome message for our new hire Oluwaseun Adeyemi "
            "(oluwaseun@example.com), who joins Dr. Kavya Iyer's team on Monday."
        ],
    },
    {
        "title": "6. Tempting the model to abbreviate labels",
        "turns": [
            "Jane Doe, John Smith and Ana Gómez share one desk. List everyone in one "
            "sentence, as briefly as you can."
        ],
    },
]


def _client() -> object:
    import anthropic

    return anthropic.Anthropic()


def _text(response: object) -> str:
    return "".join(
        block.text
        for block in response.content  # type: ignore[attr-defined]
        if block.type == "text"
    )


def ask(client: object, system: str, messages: list[dict[str, object]]) -> str:
    response = client.messages.create(  # type: ignore[attr-defined]
        model=MODEL, max_tokens=4000, system=system, messages=messages
    )
    return _text(response)


def ask_stream(client: object, system: str, messages: list[dict[str, object]]) -> Iterator[str]:
    with client.messages.stream(  # type: ignore[attr-defined]
        model=MODEL, max_tokens=4000, system=system, messages=messages
    ) as stream:
        yield from stream.text_stream


def leaked(p: depii.Pseudonymizer, sent: str) -> list[str]:
    """Real values that appear in the text sent to the model."""
    return [value for value in p.table.values() if value.lower() in sent.lower()]


def run(offline: bool) -> None:
    client = None if offline else _client()
    for case in CASES:
        print("=" * 78)
        print(case["title"])
        print("=" * 78)
        p = depii.Pseudonymizer()
        history: list[dict[str, object]] = []
        for turn in case["turns"]:  # type: ignore[attr-defined]
            history.append({"role": "user", "content": turn})
            masked = p.mask_messages(history)
            sent = str(masked[-1]["content"])
            print("\nORIGINAL:\n  " + str(turn))
            print("\nSENT TO CLAUDE:\n  " + sent)
            found = leaked(p, sent)
            print("\nLEAK CHECK: " + ("FAIL, sent " + ", ".join(found) if found else "ok"))
            if offline:
                history.append({"role": "assistant", "content": "(offline)"})
                continue
            if case.get("stream"):
                raw_parts: list[str] = []

                def tee(chunks: Iterator[str], keep: list[str] = raw_parts) -> Iterator[str]:
                    for chunk in chunks:
                        keep.append(chunk)
                        yield chunk

                print("\nFINAL, UNMASKED WHILE STREAMING:\n  ", end="")
                for piece in p.unmask_stream(tee(ask_stream(client, p.instructions, masked))):
                    print(piece, end="", flush=True)
                raw = "".join(raw_parts)
                print("\n\nCLAUDE'S REPLY AS RECEIVED:\n  " + raw)
            else:
                raw = ask(client, p.instructions, masked)
                print("\nCLAUDE'S REPLY AS RECEIVED:\n  " + raw.replace("\n", "\n  "))
                if case.get("json"):
                    body = raw.strip().removeprefix("```json").removesuffix("```").strip()
                    data = json.loads(body)
                    print("\nFINAL (JSON, UNMASKED):\n  " + json.dumps(p.unmask_obj(data)))
                else:
                    final = p.unmask(raw)
                    print("\nFINAL, UNMASKED:\n  " + final.replace("\n", "\n  "))
            unknown = p.unknown_labels(raw)
            print("\nLABELS CLAUDE INVENTED: " + (", ".join(unknown) if unknown else "none"))
            # History is kept with real values and masked again before each call;
            # the same table gives every person the same label every time.
            history.append({"role": "assistant", "content": p.unmask(raw)})
        print("\nTABLE (kept locally):", p.table, "\n")


def _key_from_user_environment() -> None:
    """On Windows, pick up a key set with setx without restarting the shell."""
    if os.environ.get("ANTHROPIC_API_KEY") or sys.platform != "win32":
        return
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, "ANTHROPIC_API_KEY")
    except OSError:
        return
    os.environ["ANTHROPIC_API_KEY"] = value


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    offline = "--offline" in sys.argv
    if not offline:
        _key_from_user_environment()
        if not os.environ.get("ANTHROPIC_API_KEY"):
            sys.exit("Set ANTHROPIC_API_KEY first, or run with --offline.")
    run(offline)
