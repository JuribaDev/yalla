# @juriba/yalla-cli (npm wrapper)

This package wraps the native [`yalla`](https://github.com/JuribaDev/yalla) Go
binary so it can be installed and executed via `npm` and `npx`.

## How it works

1. `npm install -g @juriba/yalla-cli` runs the `postinstall` script.
2. The script downloads the matching native binary from the public RustFS
   release mirror for the wrapper's `package.json` version.
3. The binary's SHA256 is verified against the release `checksums.txt` before
   it is unpacked into `node_modules/@juriba/yalla-cli/binaries/`.
4. The `yalla` bin script in `bin/yalla.js` is a thin trampoline. It execs
   the native binary with the caller's argv, inheriting stdio so stdout,
   stderr, and exit codes flow through unmodified.

## Environment overrides

| Variable                | Effect                                                                 |
|-------------------------|------------------------------------------------------------------------|
| `YALLA_VERSION`         | Force a specific release version (without the leading `v`).            |
| `YALLA_REPO`            | Use GitHub Releases for a specific `<owner>/<repo>` slug instead.      |
| `YALLA_RELEASE_BASE`    | Override the full release base URL.                                    |
| `YALLA_SKIP_DOWNLOAD=1` | Skip the postinstall download (useful in restricted CI environments). |

## Release mirror

The default public mirror is:

```text
https://s3.jsa.sa/yalla-releases/releases/download
```

Release assets must be uploaded under the tag path:

```text
releases/download/v0.1.0/yalla_0.1.0_linux_amd64.tar.gz
releases/download/v0.1.0/yalla_0.1.0_checksums.txt
```

The GitHub release workflow uploads GoReleaser archives and checksums to the
`yalla-releases` RustFS bucket. The bucket or `releases/download/` prefix must
allow unauthenticated read access so npm installs work for users without access
to the private source repository.

## Test the platform mapping

```sh
cd npm
node --test test/*.js
```

## Manual one-shot run via npx

```sh
npx @juriba/yalla-cli --version
```

`npx` invokes the same wrapper, so the binary is downloaded into a
per-invocation cache and the wrapper exec preserves stdout/stderr/exit codes
exactly.
