#!/usr/bin/env python3
"""Dockerfile checker.

Reads Dockerfiles and flags risky habits. It only reads text files: it never
builds an image or runs anything.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = bad input.
"""
import argparse
import json
import re
import sys

SEVERITIES = {"low": 1, "medium": 2, "high": 3}

SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)", re.I)
CURL_PIPE = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I)
ARCHIVE_EXT = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".txz")


class DockerfileError(Exception):
    """Raised when a Dockerfile cannot be used."""


def parse_dockerfile(text):
    """Return a list of (line_number, INSTRUCTION, arguments).

    Joins lines that end with a backslash and skips comments and blank lines.
    """
    items = []
    buffer = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if buffer and stripped.startswith("#"):
            continue
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1].rstrip() + " "
            continue
        buffer += stripped
        parts = buffer.split(None, 1)
        items.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buffer = ""
    if buffer.strip():
        parts = buffer.split(None, 1)
        items.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return items


def load_dockerfile(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return parse_dockerfile(handle.read())
    except FileNotFoundError:
        raise DockerfileError("file not found: %s" % path)
    except UnicodeDecodeError:
        raise DockerfileError("not a text file: %s" % path)
    except OSError as exc:
        raise DockerfileError("cannot read %s: %s" % (path, exc.strerror))


def _finding(rule, severity, line, message, fix):
    return {"rule": rule, "severity": severity, "line": line, "message": message, "fix": fix}


def _image_and_alias(args):
    words = [w for w in args.split() if not w.startswith("--")]
    image = words[0] if words else ""
    alias = words[2].lower() if len(words) >= 3 and words[1].lower() == "as" else None
    return image, alias


def _env_pairs(args):
    """Yield (name, value) for ENV or ARG arguments in both forms."""
    if "=" in args.split(None, 1)[0]:
        for token in re.findall(r'[^\s=]+=(?:"[^"]*"|\'[^\']*\'|\S*)', args):
            name, _, value = token.partition("=")
            yield name, value.strip("\"'")
    else:
        parts = args.split(None, 1)
        yield parts[0], parts[1].strip("\"'") if len(parts) > 1 else ""


def check_dockerfile(items):
    findings = []
    stages = []          # aliases of earlier stages
    last_from_line = None
    final_user = None    # (line, name) of the last USER in the final stage
    final_has_health = False

    for line, ins, args in items:
        if ins == "FROM":
            image, alias = _image_and_alias(args)
            last_from_line = line
            final_user = None
            final_has_health = False
            lowered = image.lower()
            is_stage_ref = lowered in stages
            if image and lowered != "scratch" and not is_stage_ref and "$" not in image:
                name = image.split("@")[0]
                tag = name.rsplit(":", 1)[1] if ":" in name.rsplit("/", 1)[-1] else None
                if "@sha256:" not in image and (tag is None or tag.lower() == "latest"):
                    findings.append(_finding(
                        "latest-tag", "medium", line,
                        "Base image '%s' has no fixed version." % image,
                        "Pin a version tag (or a digest) so builds are repeatable."))
            if alias:
                stages.append(alias)
        elif ins == "USER":
            final_user = (line, args.split(":")[0].strip().lower())
        elif ins == "HEALTHCHECK":
            if not args.strip().upper().startswith("NONE"):
                final_has_health = True
        elif ins in ("ENV", "ARG"):
            for name, value in _env_pairs(args):
                if SECRET_NAME.search(name) and value and not value.startswith("$"):
                    findings.append(_finding(
                        "secret-in-image", "high", line,
                        "%s %s has a value written in the file." % (ins, name),
                        "Never put secrets in a Dockerfile. Pass them at run time or use build secrets."))
        elif ins == "RUN":
            if CURL_PIPE.search(args):
                findings.append(_finding(
                    "curl-pipe-shell", "high", line,
                    "Downloads a script and runs it straight away.",
                    "Download it, check its checksum, then run it."))
            if re.search(r"\bchmod\b[^;&|]*\b0?777\b", args):
                findings.append(_finding(
                    "chmod-777", "medium", line,
                    "Makes files readable and writable by everyone.",
                    "Give only the permissions that are needed."))
            if re.search(r"\bsudo\b", args):
                findings.append(_finding(
                    "sudo-used", "low", line,
                    "sudo is used inside the build.",
                    "Build steps already run as root, so sudo is not needed."))
            if re.search(r"\bapt(-get)?\s+install\b", args):
                if "--no-install-recommends" not in args:
                    findings.append(_finding(
                        "apt-recommends", "low", line,
                        "apt install without --no-install-recommends adds extra packages.",
                        "Add --no-install-recommends."))
                if "/var/lib/apt/lists" not in args:
                    findings.append(_finding(
                        "apt-cache", "low", line,
                        "The apt package lists are left in the image.",
                        "End the command with rm -rf /var/lib/apt/lists/*."))
        elif ins == "ADD":
            sources = [w for w in args.split() if not w.startswith("--")][:-1]
            for source in sources:
                if re.match(r"https?://", source, re.I):
                    findings.append(_finding(
                        "add-remote-url", "medium", line,
                        "ADD downloads %s with no checksum." % source,
                        "Use curl or wget with a checksum check, or COPY a verified file."))
                elif not source.lower().endswith(ARCHIVE_EXT):
                    findings.append(_finding(
                        "add-instead-of-copy", "low", line,
                        "ADD is used for a plain file.",
                        "Use COPY unless you need ADD to unpack an archive."))
        elif ins == "EXPOSE":
            ports = [p.split("/")[0] for p in args.split()]
            if "22" in ports:
                findings.append(_finding(
                    "expose-ssh", "medium", line,
                    "Port 22 (SSH) is exposed.",
                    "Containers should not run an SSH server. Use docker exec instead."))

    if items:
        if final_user is None:
            findings.append(_finding(
                "runs-as-root", "medium", last_from_line or 1,
                "No USER line, so the container runs as root.",
                "Create a normal user and add a USER line."))
        elif final_user[1] in ("root", "0"):
            findings.append(_finding(
                "runs-as-root", "high", final_user[0],
                "The container is set to run as root.",
                "Switch to a normal user before the final command."))
        if not final_has_health:
            findings.append(_finding(
                "no-healthcheck", "low", last_from_line or 1,
                "There is no HEALTHCHECK.",
                "Add a HEALTHCHECK so the platform can tell if the app is stuck."))

    findings.sort(key=lambda f: (-SEVERITIES[f["severity"]], f["line"], f["rule"]))
    return findings


def filter_findings(findings, min_severity):
    floor = SEVERITIES[min_severity]
    return [f for f in findings if SEVERITIES[f["severity"]] >= floor]


def format_text(results):
    lines = []
    for name, findings in results:
        lines.append("%s: %d finding(s)" % (name, len(findings)))
        for f in findings:
            lines.append("  [%s] line %d  %s: %s" % (f["severity"].upper(), f["line"], f["rule"], f["message"]))
            lines.append("      Fix: %s" % f["fix"])
        if not findings:
            lines.append("  No findings.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_json(results):
    return json.dumps([{"file": n, "findings": f} for n, f in results], indent=2) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description="Check Dockerfiles for risky habits.")
    parser.add_argument("files", nargs="+", help="Dockerfile(s)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-severity", choices=tuple(SEVERITIES), default="low",
                        help="hide findings below this level")
    parser.add_argument("--fail-on", choices=tuple(SEVERITIES), default="high",
                        help="exit 1 if any finding is at or above this level")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    results = []
    worst = 0
    for path in args.files:
        try:
            items = load_dockerfile(path)
        except DockerfileError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        if not items:
            print("note: %s has no instructions." % path, file=sys.stderr)
        findings = check_dockerfile(items)
        for f in findings:
            worst = max(worst, SEVERITIES[f["severity"]])
        results.append((path, filter_findings(findings, args.min_severity)))
    output = format_json(results) if args.format == "json" else format_text(results)
    sys.stdout.write(output)
    return 1 if worst >= SEVERITIES[args.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
