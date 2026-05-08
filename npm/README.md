# yalla-cli (npm wrapper)

This package wraps the native [`yalla`](https://github.com/JuribaDev/yalla) Go
binary so it can be installed and executed via `npm` and `npx`.

## How it works

1. `npm install -g yalla-cli` runs the `postinstall` script.
2. The script downloads the matching native binary from the GitHub Release
   for the wrapper's `package.json` version.
3. The binary's SHA256 is verified against the release `checksums.txt` before
   it is unpacked into `node_modules/yalla-cli/binaries/`.
4. The `yalla` bin script in `bin/yalla.js` is a thin trampoline. It execs
   the native binary with the caller's argv, inheriting stdio so stdout,
   stderr, and exit codes flow through unmodified.

## Environment overrides

| Variable                | Effect                                                                 |
|-------------------------|------------------------------------------------------------------------|
| `YALLA_VERSION`         | Force a specific release version (without the leading `v`).            |
| `YALLA_REPO`            | Override the `<owner>/<repo>` slug used to build release URLs.         |
| `YALLA_RELEASE_BASE`    | Override the full release base URL (useful for mirrors).               |
| `YALLA_SKIP_DOWNLOAD=1` | Skip the postinstall download (useful in restricted CI environments). |

## Test the platform mapping

```sh
cd npm
node --test test
```

## Manual one-shot run via npx

```sh
npx yalla-cli --version
```

`npx` invokes the same wrapper, so the binary is downloaded into a
per-invocation cache and the wrapper exec preserves stdout/stderr/exit codes
exactly.
