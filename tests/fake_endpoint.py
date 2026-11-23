"""A local OpenAI-compatible endpoint that replays a script of replies. Used for end-to-end dry runs."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def tool(cmd, text="", xml=False):
    if xml:   # a server without a tool-call parser leaves the call in the text (Qwen3.5 format)
        return {"content": "%s\n<tool_call>\n<function=bash>\n<parameter=command>\n%s\n</parameter>\n</function>\n"
                           "</tool_call>" % (text, cmd)}
    return {"content": text, "tool_calls": [{"id": "c%d" % abs(hash(cmd)), "type": "function",
                                             "function": {"name": "bash", "arguments": json.dumps({"command": cmd})}}]}


def final(text):
    return {"content": text}


class FakeEndpoint:
    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(body)
                msg = outer.script.pop(0) if outer.script else final("(script ended)")
                data = json.dumps({"choices": [{"message": dict(role="assistant", **msg),
                                                "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}]})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data.encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/v1" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ScriptedTerminal:
    """Answers prompts from a list and records everything shown."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.shown = []
        self.prompts = []

    def say(self, s="", style=None):
        self.shown.append(s)

    def ask(self, prompt, prefill=""):
        self.prompts.append(prompt)
        if not self.answers:
            raise AssertionError("unexpected prompt: " + prompt)
        return self.answers.pop(0)

    def text(self):
        return "\n".join(self.shown)
