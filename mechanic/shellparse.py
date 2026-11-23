"""Small, quote-aware helpers for reading a bash command line.

These helpers do not try to be a full bash parser. They split a command line into simple commands
(at `|`, `||`, `&&`, `;`, `&` and newlines outside quotes), split each simple command into words,
and find the program that each simple command runs.
"""
import re
import shlex
import shutil

# Programs that run another program. The program after them is the one that matters.
WRAPPERS = {"sudo", "env", "nohup", "time", "nice", "ionice", "stdbuf", "doas", "command", "builtin",
            "exec", "xargs", "watch", "timeout", "chroot", "unbuffer", "setsid", "flock", "strace", "su", "runuser",
            "taskset", "unshare", "nsenter"}
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def segments(cmd):
    """Split at control operators outside quotes. Returns a list of (text, operator_before)."""
    out, cur, quote, i, op = [], [], None, 0, ""
    while i < len(cmd):
        c = cmd[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(cmd):
                cur.append(cmd[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c == "\\" and i + 1 < len(cmd):
            cur.append(c + cmd[i + 1])
            i += 1
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == "#" and (not cur or cur[-1][-1:].isspace()):
            while i < len(cmd) and cmd[i] != "\n":   # comment to end of line
                i += 1
            continue
        elif c in "|&;\n":
            two = cmd[i:i + 2]
            if two in ("||", "&&", ";;"):
                nxt, i = two, i + 2
            elif c == "|" and cmd[i + 1:i + 2] == "&":
                nxt, i = "|&", i + 2
            elif c == "&" and cmd[i + 1:i + 2] == ">":          # &> redirection, not a separator
                cur.append("&>")
                i += 2
                continue
            elif c == "&" and cur and cur[-1].endswith(">"):     # 2>&1
                cur.append(c)
                i += 1
                continue
            else:
                nxt, i = c, i + 1
            text = "".join(cur).strip()
            if text:
                out.append((text, op))
            cur, op = [], nxt
            continue
        else:
            cur.append(c)
        i += 1
    text = "".join(cur).strip()
    if text:
        out.append((text, op))
    return out


def words(seg):
    try:
        return shlex.split(seg, comments=False)
    except ValueError:
        return seg.split()


def program_index(ws):
    """Index of the word that names the program, after assignments and wrappers (and their options)."""
    i = 0
    while i < len(ws):
        w = ws[i]
        if ASSIGN.match(w):
            i += 1
            continue
        b = w.rsplit("/", 1)[-1]
        if b in WRAPPERS:
            # The wrapped program is the first later word that is an installed program (as in the v27 harness).
            # If none is installed here, fall back to skipping the wrapper's options and their values.
            j = next((k for k in range(i + 1, len(ws)) if not ws[k].startswith("-") and not ASSIGN.match(ws[k])
                      and shutil.which(ws[k]) and ws[k].rsplit("/", 1)[-1] not in ("-",)), None)
            if j is not None:
                i = j
                continue
            if b in ("su", "runuser", "nsenter", "unshare"):
                return i          # the command is inside a -c string or not given: treat the wrapper as the program
            i += 1
            while i < len(ws) and ws[i].startswith("-"):
                # options that take a value: sudo -u USER, timeout -s SIG, nice -n N, env -u NAME
                if ws[i] in ("-u", "-g", "-n", "-s", "-k", "-C", "-p", "-c", "-i", "-o", "-e", "-I") and b != "xargs":
                    i += 1
                elif b == "xargs" and ws[i] in ("-I", "-n", "-P", "-d", "-L", "-s", "-a", "-E"):
                    i += 1
                i += 1
            if b in ("timeout", "watch") and i < len(ws) and re.match(r"^[0-9.]+[smhd]?$", ws[i]):
                i += 1
            if b in ("chroot", "flock", "taskset") and i < len(ws):
                i += 1
            continue
        return i
    return None


def program(seg):
    ws = words(seg)
    i = program_index(ws)
    return ws[i].rsplit("/", 1)[-1] if i is not None else ""


def simple_commands(cmd):
    """[(program, argv_after_program, segment_text)] for every simple command in a command line."""
    out = []
    for text, _ in segments(cmd):
        ws = words(text)
        i = program_index(ws)
        if i is None:
            continue
        # strip redirections from the argument list; keep them in the text
        args = []
        skip = False
        for w in ws[i + 1:]:
            if skip:
                skip = False
                continue
            if re.match(r"^\d*(>>?|<|&>|>&)$", w):
                skip = True
                continue
            if re.match(r"^\d*(>>?|<|&>)\S", w) or re.match(r"^\d*>&\d$", w):
                continue
            args.append(w)
        out.append((ws[i].rsplit("/", 1)[-1], args, text))
    return out


def redirect_targets(cmd):
    """Files that a command line writes with > (overwrite) and >> (append): [(path, 'overwrite'|'append')]."""
    out = []
    for text, _ in segments(cmd):
        ws = words(text)
        for k, w in enumerate(ws):
            m = re.match(r"^(\d*|&)(>>|>\|?)(.*)$", w)
            if not m or w.startswith(">&") or re.match(r"^\d*>&\d+$", w):
                continue
            path = m.group(3) or (ws[k + 1] if k + 1 < len(ws) else "")
            if not path or path.startswith("&") or path == "/dev/null":
                continue
            out.append((path, "append" if m.group(2) == ">>" else "overwrite"))
    return out
