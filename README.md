# Dockerfile checker

![tests](https://github.com/twistedsol/dockerfile-checker/actions/workflows/tests.yml/badge.svg)

A small Python tool that reads Dockerfiles (the recipe for a container image) and flags risky habits. It only reads text files. It never builds an image or runs anything. Standard library only, no installs.

## Run it

```
python dockerfile_checker.py sample_dockerfiles/01_risky.Dockerfile
python dockerfile_checker.py sample_dockerfiles/*.Dockerfile
python dockerfile_checker.py sample_dockerfiles/02_okay_with_gaps.Dockerfile --format json
```

On Windows I use `py -3.13` instead of `python`. You can also point it at a real `Dockerfile` of your own.

Three sample Dockerfiles are included. They are made up for practice:

| File | What it is | Findings |
|---|---|---|
| `01_risky.Dockerfile` | A badly written file | 11 (3 high) |
| `02_okay_with_gaps.Dockerfile` | Looks fine but leaves gaps | 2 (0 high) |
| `03_hardened.Dockerfile` | A hardened multi-stage file | 0 |

Every finding shows the **line number** so you can jump straight to it.

## What it checks

| Rule | Severity | Flags |
|---|---|---|
| secret-in-image | high | `ENV` or `ARG` with a secret-looking name and a value written in the file |
| curl-pipe-shell | high | Downloading a script and running it straight away |
| runs-as-root | high / medium | `USER root` is high. No `USER` line at all is medium |
| latest-tag | medium | Base image with no version or `:latest` |
| add-remote-url | medium | `ADD` of a web address, with no checksum |
| chmod-777 | medium | Files writable by everyone |
| expose-ssh | medium | Port 22 exposed |
| add-instead-of-copy | low | `ADD` used for a plain file |
| sudo-used | low | `sudo` inside the build |
| apt-recommends / apt-cache | low | `apt install` without `--no-install-recommends`, or leaving the package lists behind |
| no-healthcheck | low | No `HEALTHCHECK` |

The secret rule never prints the secret value, only the name.

## Options

- `--format text|json` (default text)
- `--min-severity low|medium|high` hides findings below that level
- `--fail-on low|medium|high` sets which level makes the exit code 1 (default high)

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` bad input (missing or unreadable file).

## Test it

```
python -m unittest -v
```

46 tests cover the parser (line continuations, comments), each rule and its edges, multi-stage builds, bad input, the command line and the sample files. GitHub Actions runs them on Python 3.10 and 3.12.

## How I built it

I used AI to help write the code and tests, then ran everything myself, read each rule and checked the sample results by hand. The rules follow common container hardening advice.

## Limits

- It reads the file only. It cannot see what is inside the base image or what the build really does.
- `USER` and `HEALTHCHECK` are judged on the final stage of a multi-stage build, because that is the image that ships.
- Secret detection is by variable name (for example `PASSWORD`, `TOKEN`, `API_KEY`). A secret in a differently named variable is missed.
- It does not follow `ARG` values into the `FROM` line.
- It does not check the contents of scripts that `COPY` brings in.

## Next ideas

- Check `docker-compose.yml` files too
- Add a score out of 100
- Add an HTML report
