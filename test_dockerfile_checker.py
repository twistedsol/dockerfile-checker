import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import dockerfile_checker as dc

CLEAN = """FROM python:3.12-slim
USER appuser
HEALTHCHECK CMD true
CMD ["python"]
"""


def run(text):
    return dc.check_dockerfile(dc.parse_dockerfile(text))


def rules(text):
    return {f["rule"] for f in run(text)}


def with_(extra, head="FROM python:3.12-slim\n"):
    return head + extra + "\nUSER appuser\nHEALTHCHECK CMD true\n"


class ParseTests(unittest.TestCase):
    def test_comments_and_blank_lines(self):
        items = dc.parse_dockerfile("# note\n\nFROM alpine:3.20\n")
        self.assertEqual(items, [(3, "FROM", "alpine:3.20")])

    def test_instruction_is_case_insensitive(self):
        self.assertEqual(dc.parse_dockerfile("from alpine:3.20")[0][1], "FROM")

    def test_line_continuation(self):
        items = dc.parse_dockerfile("RUN a \\\n  && b \\\n  && c\nUSER x\n")
        self.assertEqual(items[0], (1, "RUN", "a && b && c"))
        self.assertEqual(items[1][0], 4)

    def test_comment_inside_continuation(self):
        items = dc.parse_dockerfile("RUN a \\\n# note\n  && b\n")
        self.assertEqual(items[0][2], "a && b")

    def test_trailing_backslash_at_end(self):
        items = dc.parse_dockerfile("RUN a \\\n")
        self.assertEqual(items[0][1], "RUN")

    def test_empty_text(self):
        self.assertEqual(dc.parse_dockerfile(""), [])


class RuleTests(unittest.TestCase):
    def test_clean_file(self):
        self.assertEqual(run(CLEAN), [])

    def test_latest_tag(self):
        self.assertIn("latest-tag", rules(with_("", "FROM ubuntu\n")))
        self.assertIn("latest-tag", rules(with_("", "FROM ubuntu:latest\n")))
        self.assertNotIn("latest-tag", rules(with_("", "FROM ubuntu:22.04\n")))

    def test_digest_counts_as_pinned(self):
        self.assertNotIn("latest-tag", rules(with_("", "FROM ubuntu@sha256:abc123\n")))

    def test_registry_port_is_not_a_tag(self):
        self.assertIn("latest-tag", rules(with_("", "FROM localhost:5000/app\n")))
        self.assertNotIn("latest-tag", rules(with_("", "FROM localhost:5000/app:1.2\n")))

    def test_scratch_variables_and_stage_references(self):
        self.assertNotIn("latest-tag", rules(with_("", "FROM scratch\n")))
        self.assertNotIn("latest-tag", rules(with_("", "FROM ${BASE}\n")))
        multi = "FROM golang:1.22 AS build\nFROM build\nUSER a\nHEALTHCHECK CMD true\n"
        self.assertNotIn("latest-tag", rules(multi))

    def test_from_platform_flag(self):
        self.assertIn("latest-tag", rules(with_("", "FROM --platform=linux/amd64 ubuntu\n")))

    def test_secret_in_env(self):
        self.assertIn("secret-in-image", rules(with_("ENV DB_PASSWORD=hunter2")))
        self.assertIn("secret-in-image", rules(with_("ENV API_KEY abc123")))
        self.assertIn("secret-in-image", rules(with_("ARG GITHUB_TOKEN=ghp_x")))

    def test_secret_name_without_value_is_fine(self):
        self.assertNotIn("secret-in-image", rules(with_("ARG GITHUB_TOKEN")))
        self.assertNotIn("secret-in-image", rules(with_("ENV DB_PASSWORD=$DB_PASSWORD")))
        self.assertNotIn("secret-in-image", rules(with_("ENV APP_ENV=production")))

    def test_secret_message_does_not_print_the_value(self):
        text = dc.format_text([("f", run(with_("ENV DB_PASSWORD=hunter2")))])
        self.assertNotIn("hunter2", text)

    def test_several_pairs_on_one_line(self):
        found = rules(with_("ENV A=1 SECRET_KEY=zzz"))
        self.assertIn("secret-in-image", found)

    def test_curl_pipe_shell(self):
        self.assertIn("curl-pipe-shell", rules(with_("RUN curl -fsSL https://x.test/i.sh | sh")))
        self.assertIn("curl-pipe-shell", rules(with_("RUN wget -qO- https://x.test/i.sh | bash")))
        self.assertIn("curl-pipe-shell", rules(with_("RUN curl https://x.test | sudo sh")))
        self.assertNotIn("curl-pipe-shell", rules(with_("RUN curl -o a.sh https://x.test && sh a.sh")))

    def test_chmod_777(self):
        self.assertIn("chmod-777", rules(with_("RUN chmod 777 /app")))
        self.assertIn("chmod-777", rules(with_("RUN chmod -R 777 /app")))
        self.assertNotIn("chmod-777", rules(with_("RUN chmod 755 /app")))

    def test_sudo(self):
        self.assertIn("sudo-used", rules(with_("RUN sudo make install")))

    def test_apt_rules(self):
        both = rules(with_("RUN apt-get install -y curl"))
        self.assertIn("apt-recommends", both)
        self.assertIn("apt-cache", both)
        good = with_("RUN apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*")
        self.assertNotIn("apt-recommends", rules(good))
        self.assertNotIn("apt-cache", rules(good))

    def test_add_remote_url(self):
        self.assertIn("add-remote-url", rules(with_("ADD https://x.test/a.tar.gz /a.tar.gz")))

    def test_add_local_file_vs_archive(self):
        self.assertIn("add-instead-of-copy", rules(with_("ADD config.ini /etc/config.ini")))
        self.assertNotIn("add-instead-of-copy", rules(with_("ADD app.tar.gz /opt/")))

    def test_expose_ssh(self):
        self.assertIn("expose-ssh", rules(with_("EXPOSE 22")))
        self.assertIn("expose-ssh", rules(with_("EXPOSE 8080 22/tcp")))
        self.assertNotIn("expose-ssh", rules(with_("EXPOSE 2222")))

    def test_runs_as_root_when_no_user(self):
        found = [f for f in run("FROM python:3.12\nHEALTHCHECK CMD true\n") if f["rule"] == "runs-as-root"]
        self.assertEqual(found[0]["severity"], "medium")

    def test_explicit_root_is_high(self):
        found = [f for f in run("FROM python:3.12\nUSER root\nHEALTHCHECK CMD true\n") if f["rule"] == "runs-as-root"]
        self.assertEqual(found[0]["severity"], "high")
        self.assertEqual(found[0]["line"], 2)

    def test_user_zero_and_group_form(self):
        self.assertIn("runs-as-root", rules("FROM python:3.12\nUSER 0\nHEALTHCHECK CMD true\n"))
        self.assertNotIn("runs-as-root", rules("FROM python:3.12\nUSER app:app\nHEALTHCHECK CMD true\n"))

    def test_only_final_stage_user_counts(self):
        text = ("FROM golang:1.22 AS build\nUSER root\nRUN make\n"
                "FROM alpine:3.20\nUSER app\nHEALTHCHECK CMD true\n")
        self.assertNotIn("runs-as-root", rules(text))

    def test_root_in_final_stage_is_found_even_if_build_stage_is_fine(self):
        text = ("FROM golang:1.22 AS build\nUSER app\n"
                "FROM alpine:3.20\nHEALTHCHECK CMD true\n")
        self.assertIn("runs-as-root", rules(text))

    def test_healthcheck(self):
        self.assertIn("no-healthcheck", rules("FROM python:3.12\nUSER a\n"))
        self.assertIn("no-healthcheck", rules("FROM python:3.12\nUSER a\nHEALTHCHECK NONE\n"))
        self.assertNotIn("no-healthcheck", rules("FROM python:3.12\nUSER a\nHEALTHCHECK CMD true\n"))

    def test_empty_file_has_no_findings(self):
        self.assertEqual(run(""), [])

    def test_line_numbers(self):
        found = [f for f in run(with_("ENV DB_PASSWORD=x")) if f["rule"] == "secret-in-image"]
        self.assertEqual(found[0]["line"], 2)


class OutputTests(unittest.TestCase):
    def test_sorted_high_first(self):
        order = [dc.SEVERITIES[f["severity"]] for f in run("FROM ubuntu\nENV A_TOKEN=x\n")]
        self.assertEqual(order, sorted(order, reverse=True))

    def test_filter(self):
        high = dc.filter_findings(run("FROM ubuntu\nENV A_TOKEN=x\n"), "high")
        self.assertTrue(high)
        self.assertTrue(all(f["severity"] == "high" for f in high))

    def test_text_and_json(self):
        results = [("Dockerfile", run("FROM ubuntu\n"))]
        self.assertIn("latest-tag", dc.format_text(results))
        self.assertEqual(json.loads(dc.format_json(results))[0]["file"], "Dockerfile")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, content, mode="w"):
        path = os.path.join(self.dir.name, name)
        with open(path, mode) as handle:
            handle.write(content)
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = dc.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_clean_exit_0(self):
        code, out, _ = self.run_cli(self.write("Dockerfile", CLEAN))
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_high_exit_1(self):
        path = self.write("Dockerfile", "FROM python:3.12\nUSER root\n")
        self.assertEqual(self.run_cli(path)[0], 1)

    def test_fail_on(self):
        path = self.write("Dockerfile", "FROM ubuntu\nUSER a\nHEALTHCHECK CMD true\n")
        self.assertEqual(self.run_cli(path)[0], 0)
        self.assertEqual(self.run_cli(path, "--fail-on", "medium")[0], 1)

    def test_min_severity(self):
        path = self.write("Dockerfile", "FROM ubuntu\nUSER a\n")
        _, out, _ = self.run_cli(path, "--min-severity", "medium")
        self.assertNotIn("no-healthcheck", out)

    def test_json(self):
        path = self.write("Dockerfile", "FROM ubuntu\nUSER a\nHEALTHCHECK CMD true\n")
        _, out, _ = self.run_cli(path, "--format", "json")
        self.assertEqual(json.loads(out)[0]["findings"][0]["rule"], "latest-tag")

    def test_missing_file(self):
        code, _, err = self.run_cli(os.path.join(self.dir.name, "none"))
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_binary_file(self):
        code, _, err = self.run_cli(self._binary())
        self.assertEqual(code, 2)
        self.assertIn("not a text file", err)

    def _binary(self):
        path = os.path.join(self.dir.name, "bin")
        with open(path, "wb") as handle:
            handle.write(b"\xff\xfe\x00\x80")
        return path

    def test_empty_file_note(self):
        code, out, err = self.run_cli(self.write("Dockerfile", ""))
        self.assertEqual(code, 0)
        self.assertIn("no instructions", err)

    def test_several_files(self):
        a = self.write("a", CLEAN)
        b = self.write("b", "FROM python:3.12\nUSER root\n")
        code, out, _ = self.run_cli(a, b)
        self.assertEqual(code, 1)
        self.assertEqual(out.count("finding(s)"), 2)


class SampleTests(unittest.TestCase):
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_dockerfiles")

    def findings(self, name):
        return dc.check_dockerfile(dc.load_dockerfile(os.path.join(self.base, name)))

    def test_risky(self):
        found = self.findings("01_risky.Dockerfile")
        self.assertEqual(len(found), 11)
        self.assertEqual(sum(f["severity"] == "high" for f in found), 3)

    def test_okay_with_gaps(self):
        self.assertEqual({f["rule"] for f in self.findings("02_okay_with_gaps.Dockerfile")},
                         {"runs-as-root", "no-healthcheck"})

    def test_hardened(self):
        self.assertEqual(self.findings("03_hardened.Dockerfile"), [])


if __name__ == "__main__":
    unittest.main()
