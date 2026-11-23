"""A minimal client for OpenAI-compatible /v1/chat/completions endpoints (Kindi, vLLM, llama.cpp server, ...)."""
import json
import re
import urllib.error
import urllib.request

TOOL_XML = re.compile(r"<tool_call>\s*<function=([^>]+)>(.*?)</function>\s*</tool_call>", re.S)
PARAM_XML = re.compile(r"<parameter=([^>]+)>(.*?)</parameter>", re.S)
TOOL_JSON = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)


class EndpointError(RuntimeError):
    pass


def parse_text_tool_calls(text):
    """Tool calls that a server left in the message text (no tool-call parser on the server side)."""
    calls = []
    for m in TOOL_XML.finditer(text or ""):
        args = {p.group(1).strip(): p.group(2).strip("\n") for p in PARAM_XML.finditer(m.group(2))}
        calls.append({"id": "call_%d" % len(calls), "type": "function",
                      "function": {"name": m.group(1).strip(), "arguments": json.dumps(args)}})
    if not calls:
        for m in TOOL_JSON.finditer(text or ""):
            try:
                o = json.loads(m.group(1))
                calls.append({"id": "call_%d" % len(calls), "type": "function",
                              "function": {"name": o.get("name", ""), "arguments": json.dumps(o.get("arguments", {}))}})
            except ValueError:
                pass
    content = re.split(r"<tool_call>", text or "")[0].strip()
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
    return content, calls


def command_of(call):
    args = call.get("function", {}).get("arguments", {})
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            return args
    return args.get("command", "") if isinstance(args, dict) else ""


class Client:
    def __init__(self, base_url, model=None, api_key=None, timeout=300, max_tokens=1024, temperature=0.0):
        self.url = base_url.rstrip("/")
        if not self.url.endswith("/v1"):
            self.url += "/v1"
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature

    def chat(self, messages, tools=None):
        body = {"messages": messages, "max_tokens": self.max_tokens, "temperature": self.temperature,
                "chat_template_kwargs": {"enable_thinking": False}}
        if self.model:
            body["model"] = self.model
        if tools:
            body["tools"] = tools
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        req = urllib.request.Request(self.url + "/chat/completions", json.dumps(body).encode(), headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            raise EndpointError("HTTP %s from %s: %s" % (e.code, self.url, e.read()[:300].decode("utf-8", "replace")))
        except (urllib.error.URLError, OSError) as e:
            raise EndpointError("cannot reach %s: %s" % (self.url, e))
        try:
            choice = data["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError, TypeError):
            raise EndpointError("unexpected reply from %s: %s" % (self.url, str(data)[:300]))
        content = msg.get("content") or ""
        calls = msg.get("tool_calls") or []
        if not calls:
            content, calls = parse_text_tool_calls(content)
        else:
            content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
        return {"content": content, "tool_calls": calls, "finish": choice.get("finish_reason", "stop")}
