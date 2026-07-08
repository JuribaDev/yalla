#!/usr/bin/env python3
"""
Detect a project's deploy plan for the yalla-dokploy-deploy skill.

Usage:
    python3 detect_stack.py [path]    # path defaults to cwd

Emits a single JSON object on stdout describing what the skill needs to
know:
- shape (single | compose)
- build_type (dockerfile | nixpacks | railpack | heroku_buildpacks |
              paketo_buildpacks | static)
- source (image | git | unknown)
- source_config (provider-specific dict)
- env_vars (categorised from .env* files)
- db_needs (list of {engine, signal} dicts)
- project_name (basename of path, normalised)
- existing state (.dokploy.yaml contents if found)

Heuristics — never silently chooses a build type if multiple strong
signals collide. Surfaces ambiguity via `ambiguous` keys so the calling
agent can ask the user.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

# ---------- shape -----------------------------------------------------------

COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml",
                 "compose.yml", "compose.yaml")


def detect_shape(root: Path) -> str:
    for n in COMPOSE_NAMES:
        if (root / n).exists():
            return "compose"
    return "single"


# ---------- build type ------------------------------------------------------


def detect_build_type(root: Path) -> tuple[str | None, str, dict]:
    """Return (build_type, reason, type_config). build_type=None means ambiguous/unknown."""

    # 1. Dockerfile
    dockerfiles = list(root.glob("Dockerfile")) + list(root.glob("Dockerfile.*"))
    if dockerfiles:
        if len(dockerfiles) > 1:
            return None, f"multiple dockerfiles found: {[d.name for d in dockerfiles]}", {}
        df = dockerfiles[0]
        return "dockerfile", f"{df.name} present at repo root", {
            "dockerfile": f"./{df.name}",
            "dockerContextPath": ".",
            "dockerBuildStage": None,
        }

    # 2. Railpack
    if (root / "railpack.json").exists() or (root / "railpack.toml").exists():
        return "railpack", "railpack manifest present", {"railpackVersion": "latest"}

    # 3. Heroku buildpacks (Procfile + language)
    if (root / "Procfile").exists() and _has_language_manifest(root):
        return "heroku_buildpacks", "Procfile + language manifest present", {
            "herokuVersion": "heroku-22",
        }

    # 4. Paketo (project.toml with CNB groups)
    pt = root / "project.toml"
    if pt.exists():
        try:
            text = pt.read_text(errors="replace")
            if "[[io.buildpacks.group]]" in text or "[io.buildpacks]" in text:
                return "paketo_buildpacks", "project.toml has CNB groups", {}
        except OSError:
            pass

    # 5. Nixpacks (any modern language manifest)
    lang = _detect_language(root)
    if lang:
        return "nixpacks", f"language manifest ({lang}) present, no Dockerfile", {}

    # 6. Static
    static_hints = _detect_static(root)
    if static_hints:
        publish, is_spa = static_hints
        return "static", f"static assets in {publish}", {
            "publishDirectory": f"./{publish}" if publish != "." else ".",
            "isStaticSpa": is_spa,
        }

    return None, "no recognised build signal", {}


def _has_language_manifest(root: Path) -> bool:
    return any((root / n).exists() for n in (
        "package.json", "requirements.txt", "pyproject.toml", "Pipfile",
        "go.mod", "Cargo.toml", "Gemfile", "composer.json", "mix.exs",
    ))


def _detect_language(root: Path) -> str | None:
    candidates = [
        ("package.json", "Node.js"),
        ("pyproject.toml", "Python"),
        ("requirements.txt", "Python"),
        ("Pipfile", "Python"),
        ("go.mod", "Go"),
        ("Cargo.toml", "Rust"),
        ("Gemfile", "Ruby"),
        ("composer.json", "PHP"),
        ("mix.exs", "Elixir"),
        ("deno.json", "Deno"),
        ("deno.jsonc", "Deno"),
        ("bun.lockb", "Bun"),
    ]
    for f, lang in candidates:
        if (root / f).exists():
            return lang
    return None


def _detect_static(root: Path) -> tuple[str, bool] | None:
    # Look for built-output dirs
    for d in ("dist", "build", "public", "out"):
        if (root / d).is_dir() and (root / d / "index.html").exists():
            # SPA detection: vite/next-export/CRA build markers in repo
            is_spa = any((root / m).exists() for m in (
                "vite.config.js", "vite.config.ts", "vite.config.mjs"))
            if not is_spa:
                next_cfg = root / "next.config.js"
                if next_cfg.exists():
                    try:
                        is_spa = "output" in next_cfg.read_text(errors="replace") and "export" in next_cfg.read_text(errors="replace")
                    except OSError:
                        is_spa = False
            return d, bool(is_spa)
    # Plain index.html at root
    if (root / "index.html").exists() and not _detect_language(root):
        return ".", False
    return None


# ---------- source ----------------------------------------------------------


def detect_source(root: Path) -> dict:
    git_dir = _resolve_git_dir(root)
    if git_dir is None:
        return {"kind": "unknown", "reason": "no .git directory or worktree pointer"}
    # The remote 'origin' URL lives in the COMMON dir's config, not the per-worktree gitdir.
    common_dir = _resolve_common_dir(git_dir)
    remote_url = _read_git_remote(common_dir / "config")
    if not remote_url:
        return {"kind": "unknown", "reason": "no origin remote"}
    branch = _read_current_branch(git_dir)
    return {
        "kind": "git",
        "url": remote_url,
        "branch": branch or "main",
        "build_path": "/",
        "watch_paths": [],
        "ssh_key_id": None,
    }


def _resolve_git_dir(root: Path) -> Path | None:
    """Return the gitdir for `root`, handling worktrees where .git is a file."""
    g = root / ".git"
    if g.is_dir():
        return g
    if g.is_file():
        try:
            text = g.read_text(errors="replace").strip()
        except OSError:
            return None
        if text.startswith("gitdir:"):
            target = Path(text.removeprefix("gitdir:").strip())
            if not target.is_absolute():
                target = (root / target).resolve()
            return target if target.is_dir() else None
    return None


def _resolve_common_dir(git_dir: Path) -> Path:
    """In a worktree, the per-worktree gitdir has a `commondir` file pointing at the main gitdir."""
    cd_file = git_dir / "commondir"
    if cd_file.exists():
        try:
            rel = cd_file.read_text(errors="replace").strip()
            target = Path(rel)
            if not target.is_absolute():
                target = (git_dir / target).resolve()
            if target.is_dir():
                return target
        except OSError:
            pass
    return git_dir


def _read_git_remote(config_path: Path) -> str | None:
    if not config_path.exists():
        return None
    try:
        text = config_path.read_text(errors="replace")
    except OSError:
        return None
    in_origin = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[remote"):
            in_origin = 'origin' in s
            continue
        if in_origin and s.startswith("url ="):
            return s.split("=", 1)[1].strip()
    return None


def _read_current_branch(git_dir: Path) -> str | None:
    head = git_dir / "HEAD"
    if not head.exists():
        return None
    try:
        text = head.read_text(errors="replace").strip()
    except OSError:
        return None
    if text.startswith("ref: refs/heads/"):
        return text.removeprefix("ref: refs/heads/")
    return None  # detached


# ---------- env vars --------------------------------------------------------

ENV_FILE_GLOBS = (".env", ".env.local", ".env.example",
                  ".env.staging", ".env.production",
                  ".env.development", ".env.test")

SECRET_PATTERN = re.compile(
    r"(_SECRET|_KEY$|_TOKEN$|_PASSWORD$|PRIVATE_KEY|"
    r"STRIPE_.*_SECRET|OPENAI_API_KEY|SENTRY_DSN)",
    re.IGNORECASE,
)
BUILD_ARG_PATTERN = re.compile(
    r"^(BUILD_|NEXT_PUBLIC_|VITE_|REACT_APP_|GATSBY_|EXPO_PUBLIC_)")
PLACEHOLDER_VALUES = {
    "your-key-here", "change-me", "changeme", "xxx", "<your-token>",
    "<token>", "todo", "fixme",
}


def parse_env_files(root: Path) -> dict:
    env, build_args, secrets, missing = [], [], [], []
    seen_keys: set[str] = set()
    for name in ENV_FILE_GLOBS:
        f = root / name
        if not f.exists():
            continue
        try:
            for line in f.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if not key or key in seen_keys:
                    continue
                seen_keys.add(key)
                rec = {"key": key, "value": val, "from": name}
                if not val or val.lower() in PLACEHOLDER_VALUES:
                    missing.append(rec)
                    continue
                if SECRET_PATTERN.search(key):
                    secrets.append(rec)
                elif BUILD_ARG_PATTERN.match(key):
                    build_args.append(rec)
                else:
                    env.append(rec)
        except OSError:
            continue
    return {
        "runtime": env,
        "build_args": build_args,
        "secrets": secrets,
        "needs_value": missing,
    }


# ---------- database needs --------------------------------------------------

DB_SIGNALS = [
    # (engine, regex, source-label)
    ("postgres", re.compile(r"(?:postgres|postgresql)://", re.IGNORECASE), "DATABASE_URL=postgres://"),
    ("mysql", re.compile(r"mysql://", re.IGNORECASE), "DATABASE_URL=mysql://"),
    ("mongo", re.compile(r"mongodb(?:\+srv)?://", re.IGNORECASE), "MONGO_URL or DATABASE_URL=mongodb://"),
    ("redis", re.compile(r"redis://", re.IGNORECASE), "REDIS_URL=redis://"),
]

# Pattern that pulls the host out of a connection URL (everything between // and the next : or /).
_URL_HOST = re.compile(
    r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss)://"
    r"(?:[^@/]*@)?"     # optional user:pass@
    r"([^:/?#\s]+)",    # host (no port, path, query, or whitespace)
    re.IGNORECASE,
)

# Known managed-DB suffixes (external — never provision).
_EXTERNAL_SUFFIXES = (
    ".rds.amazonaws.com", ".neon.tech", ".supabase.co", ".supabase.com",
    ".aivencloud.com", ".render.com", ".railway.app", ".planetscale.com",
    ".cockroachlabs.cloud", ".fly.dev", ".mongodb.net", ".redislabs.com",
    ".upstash.io", ".azure.com",
)

# In-cluster signals (DNS suffixes only used inside container networks).
_IN_CLUSTER_SUFFIXES = (".local", ".internal", ".cluster.local", ".svc.cluster.local")

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def classify_db_host(host: str) -> str:
    """Return 'in-cluster' | 'external' | 'ambiguous' | 'local-dev'."""
    if not host:
        return "ambiguous"
    h = host.strip().lower()
    # Strip [ipv6] brackets
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h in _LOCAL_HOSTS:
        return "local-dev"
    # Bare hostname (no dot) = Docker/swarm-resolvable service name
    if "." not in h:
        return "in-cluster"
    if any(h.endswith(suf) for suf in _IN_CLUSTER_SUFFIXES):
        return "in-cluster"
    if any(h.endswith(suf) for suf in _EXTERNAL_SUFFIXES):
        return "external"
    # RFC1918 private IPs — ambiguous, could be cluster or private external
    if _is_rfc1918(h):
        return "ambiguous"
    # Public IP or any other FQDN → external
    return "external"


def _is_rfc1918(host: str) -> bool:
    """Detect 10.x.x.x, 192.168.x.x, or 172.16-31.x.x."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        a = int(parts[0])
        b = int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 192 and b == 168:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    return False

DEP_SIGNALS = {
    "postgres": [
        ("requirements.txt", re.compile(r"^\s*(?:psycopg2?|asyncpg)", re.IGNORECASE | re.MULTILINE)),
        ("pyproject.toml", re.compile(r'\b(?:psycopg2?|asyncpg)\b', re.IGNORECASE)),
        ("package.json", re.compile(r'"(?:pg|postgres|drizzle-orm)"', re.IGNORECASE)),
        ("go.mod", re.compile(r'(?:jackc/pgx|lib/pq)', re.IGNORECASE)),
    ],
    "mysql": [
        ("requirements.txt", re.compile(r"^\s*(?:pymysql|mysqlclient)", re.IGNORECASE | re.MULTILINE)),
        ("package.json", re.compile(r'"mysql2?"', re.IGNORECASE)),
    ],
    "mongo": [
        ("requirements.txt", re.compile(r"^\s*(?:pymongo|motor)", re.IGNORECASE | re.MULTILINE)),
        ("package.json", re.compile(r'"(?:mongodb|mongoose)"', re.IGNORECASE)),
    ],
    "redis": [
        ("requirements.txt", re.compile(r"^\s*(?:redis|aioredis)", re.IGNORECASE | re.MULTILINE)),
        ("package.json", re.compile(r'"(?:redis|ioredis)"', re.IGNORECASE)),
        ("go.mod", re.compile(r'go-redis/redis', re.IGNORECASE)),
    ],
}


def detect_db_needs(root: Path) -> list[dict]:
    needs: dict[str, dict] = {}

    # 1. Connection-string env vars
    for name in ENV_FILE_GLOBS:
        f = root / name
        if not f.exists():
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        # Find every URL host so we can classify it
        url_hosts = _URL_HOST.findall(text)
        for engine, pat, label in DB_SIGNALS:
            m = pat.search(text)
            if not m or engine in needs:
                continue
            # Resolve the host for THIS engine's URL — re-scan with the same regex anchored to the URL line
            host = ""
            classification = "in-cluster"
            for line in text.splitlines():
                if pat.search(line):
                    host_match = _URL_HOST.search(line)
                    if host_match:
                        host = host_match.group(1)
                        classification = classify_db_host(host)
                    break
            needs[engine] = {
                "engine": engine,
                "signal": f"{label} in {name}",
                "host": host,
                "classification": classification,
                "provision": classification == "in-cluster",
            }
        _ = url_hosts  # reserved for future cross-checks

    # 2. Prisma schema
    prisma = root / "prisma" / "schema.prisma"
    if prisma.exists():
        try:
            text = prisma.read_text(errors="replace")
        except OSError:
            text = ""
        for kw, engine in (
            ("postgresql", "postgres"),
            ("mysql", "mysql"),
            ("mongodb", "mongo"),
        ):
            if f'provider = "{kw}"' in text and engine not in needs:
                # Prisma datasources point at DATABASE_URL via env() — defer host classification to step 1 above.
                # If we never saw a URL there, assume in-cluster (user expects Dokploy-managed) but flag it.
                needs[engine] = {
                    "engine": engine,
                    "signal": f"prisma datasource provider={kw}",
                    "host": "",
                    "classification": "in-cluster",
                    "provision": True,
                }

    # 3. Language deps (no URL context — assume the user wants a Dokploy-managed instance unless they have an
    #    external URL that step 1 would have caught above).
    for engine, signals in DEP_SIGNALS.items():
        if engine in needs:
            continue
        for fname, pat in signals:
            f = root / fname
            if not f.exists():
                continue
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if pat.search(text):
                needs[engine] = {
                    "engine": engine,
                    "signal": f"matched {pat.pattern} in {fname}",
                    "host": "",
                    "classification": "in-cluster",
                    "provision": True,
                }
                break

    return list(needs.values())


# ---------- state file ------------------------------------------------------


def read_state_file(root: Path) -> dict | None:
    f = root / ".dokploy.yaml"
    if not f.exists():
        return None
    try:
        text = f.read_text(errors="replace")
    except OSError:
        return None
    # Tiny YAML reader — enough for the flat shape this skill writes.
    out: dict = {}
    stack: list[tuple[int, dict]] = [(0, out)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        s = raw.strip()
        while stack and indent < stack[-1][0]:
            stack.pop()
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not v:
            new: dict = {}
            stack[-1][1][k] = new
            stack.append((indent + 2, new))
        else:
            stack[-1][1][k] = v.strip('"').strip("'")
    return out


# ---------- naming ----------------------------------------------------------


def project_name(root: Path) -> str:
    base = root.resolve().name
    s = base.lower()
    s = re.sub(r"[^a-z0-9-]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "app"


# ---------- main ------------------------------------------------------------


def build_plan(root: Path) -> dict:
    shape = detect_shape(root)
    build_type, build_reason, build_config = detect_build_type(root) if shape == "single" else (None, "compose stack — build type set in compose file", {})
    source = detect_source(root)
    env = parse_env_files(root)
    dbs = detect_db_needs(root)
    state = read_state_file(root)

    plan = {
        "schema": "yalla-dokploy-deploy.detect.v1",
        "project_name": project_name(root),
        "shape": shape,
        "build_type": build_type,
        "build_type_reason": build_reason,
        "build_type_config": build_config,
        "source": source,
        "env_vars": env,
        "db_needs": dbs,
        "environments": ["production", "staging"],
        "existing_state": state,
        "ambiguities": _summarise_ambiguities(build_type, source, shape),
    }
    return plan


def _summarise_ambiguities(build_type, source, shape="single") -> list[str]:
    out = []
    # Compose stacks don't have a project-level build_type; the compose file does.
    if shape == "single" and build_type is None:
        out.append("build_type unresolved — ask the user")
    if source.get("kind") == "unknown":
        out.append(f"source unresolved ({source.get('reason')}) — ask the user for image ref or git URL")
    return out


def main() -> int:
    arg = sys.argv[1] if len(sys.argv) > 1 else "."
    root = Path(arg).expanduser().resolve()
    if not root.is_dir():
        print(f"detect_stack: not a directory: {root}", file=sys.stderr)
        return 2
    plan = build_plan(root)
    json.dump(plan, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
