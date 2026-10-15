"""Round-trip test cases against Claude: mask, send, unmask, check.

    python examples/claude_test_cases.py            # API key, else the Claude CLI
    python examples/claude_test_cases.py --cli      # Claude Code CLI login, no key
    python examples/claude_test_cases.py --offline  # show what would be sent

Each case prints the original text, what Claude actually receives, Claude's
reply as it came back (labels only), and the reply with real values put back.
Two checks run on every case: no real value may appear in what is sent, and
any label Claude invented is listed.

The API backend needs `pip install anthropic` and uses a few cents of credit;
the CLI backend uses your Claude Code login and plan.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
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


class ApiBackend:
    """Calls the Claude API through the anthropic SDK. Needs ANTHROPIC_API_KEY."""

    name = f"Claude API ({MODEL})"

    def __init__(self) -> None:
        import anthropic

        self.client = anthropic.Anthropic()

    def ask(self, system: str, messages: list[dict[str, object]]) -> str:
        response = self.client.messages.create(
            model=MODEL, max_tokens=4000, system=system, messages=messages
        )
        return "".join(block.text for block in response.content if block.type == "text")

    def ask_stream(self, system: str, messages: list[dict[str, object]]) -> Iterator[str]:
        with self.client.messages.stream(
            model=MODEL, max_tokens=4000, system=system, messages=messages
        ) as stream:
            yield from stream.text_stream


class CliBackend:
    """Calls Claude through the Claude Code CLI (`claude -p`), using its login.

    Every call runs with no tools, no hooks, no saved session and an empty
    working folder, so nothing from the local setup reaches the model.
    """

    name = "Claude Code CLI (claude -p)"

    def __init__(self) -> None:
        self.folder = tempfile.mkdtemp(prefix="depii-cli-")

    def _command(self, system: str, *extra: str) -> list[str]:
        return [
            shutil.which("claude") or "claude", "-p", "--system-prompt", system,
            "--tools", "", "--settings", '{"disableAllHooks": true}',
            "--no-session-persistence", *extra,
        ]  # fmt: skip

    @staticmethod
    def _transcript(messages: list[dict[str, object]]) -> str:
        """The CLI takes one prompt, so earlier turns are written out above the last."""
        if len(messages) == 1:
            return str(messages[0]["content"])
        lines = ["Conversation so far:"]
        for message in messages[:-1]:
            lines.append(f"{message['role'].capitalize()}: {message['content']}")  # type: ignore[attr-defined]
        lines.append("\nReply to this latest message:\n" + str(messages[-1]["content"]))
        return "\n".join(lines)

    def ask(self, system: str, messages: list[dict[str, object]]) -> str:
        done = subprocess.run(  # noqa: S603
            self._command(system, "--output-format", "text"),
            input=self._transcript(messages),
            capture_output=True, text=True, encoding="utf-8", cwd=self.folder,
            timeout=300, check=True,
        )  # fmt: skip
        return done.stdout.strip()

    def ask_stream(self, system: str, messages: list[dict[str, object]]) -> Iterator[str]:
        command = self._command(
            system, "--output-format", "stream-json", "--include-partial-messages", "--verbose"
        )
        with subprocess.Popen(  # noqa: S603
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", cwd=self.folder,
        ) as process:  # fmt: skip
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(self._transcript(messages))
            process.stdin.close()
            for line in process.stdout:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                inner = event.get("event", {}) if event.get("type") == "stream_event" else {}
                delta = inner.get("delta", {})
                if inner.get("type") == "content_block_delta" and delta.get("type") == "text_delta":
                    yield delta["text"]


def leaked(p: depii.Pseudonymizer, sent: str) -> list[str]:
    """Real values that appear in the text sent to the model."""
    return [value for value in p.table.values() if value.lower() in sent.lower()]


def run(backend: ApiBackend | CliBackend | None) -> None:
    offline = backend is None
    if backend is not None:
        print("Backend:", backend.name)
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
                for piece in p.unmask_stream(tee(backend.ask_stream(p.instructions, masked))):
                    print(piece, end="", flush=True)
                raw = "".join(raw_parts)
                print("\n\nCLAUDE'S REPLY AS RECEIVED:\n  " + raw)
            else:
                raw = backend.ask(p.instructions, masked)
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
    if "--offline" in sys.argv:
        run(None)
        sys.exit()
    _key_from_user_environment()
    if "--cli" not in sys.argv and os.environ.get("ANTHROPIC_API_KEY"):
        run(ApiBackend())
    elif shutil.which("claude"):
        run(CliBackend())
    else:
        sys.exit("Set ANTHROPIC_API_KEY or install the Claude Code CLI, or use --offline.")
